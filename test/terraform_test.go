package test

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gruntwork-io/terratest/modules/k8s"
	"github.com/gruntwork-io/terratest/modules/logger"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"software.sslmate.com/src/go-pkcs12"
)

type syncedCertificate struct {
	Name        string `json:"name"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

// fetchSensitiveOutput suppresses logging of sensitive outputs
func fetchSensitiveOutput(t *testing.T, options *terraform.Options, name string) string {
	defer func() {
		options.Logger = nil
	}()
	options.Logger = logger.Discard
	return terraform.OutputContext(t, t.Context(), options, name)
}

func TestTerraformAzureAKS(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	// Try to start Docker Desktop on macOS or Windows (ignore any errors)
	if osName := runtime.GOOS; osName == "darwin" || osName == "windows" {
		// Map GOOS to a human-friendly name
		friendly := map[string]string{
			"darwin":  "macOS",
			"windows": "Windows",
		}[osName]

		t.Logf("Detected %s: attempting to start Docker Desktop", friendly)
		if out, err := exec.Command("docker", "desktop", "start").CombinedOutput(); err != nil {
			t.Logf("Ignoring error starting Docker Desktop: %v — output: %s", err, string(out))
		}
	}

	// Read any required Docker auth environment variables
	dockerUsername := os.Getenv("DOCKER_REGISTRY_USER")
	dockerPassword := os.Getenv("DOCKER_REGISTRY_PASS")

	// Start from the previous published release and upgrade to this branch when TEST_SCENARIO is "upgrade"
	upgrade := os.Getenv("TEST_SCENARIO") == "upgrade"

	terraformOptions := &terraform.Options{
		// Terraform folder
		TerraformDir: "./terraform",

		TerraformBinary: "tofu",

		// Pass Terraform variables
		Vars: map[string]interface{}{
			"auto_cleanup":             true,
			"install_previous_release": upgrade,
		},

		// Pass Docker auth environment variables to Terraform's shell environment
		EnvVars: map[string]string{
			"DOCKER_REGISTRY_USER": dockerUsername,
			"DOCKER_REGISTRY_PASS": dockerPassword,
		},

		// Retry settings for Terraform apply/destroy
		MaxRetries:         3,
		TimeBetweenRetries: 30 * time.Second,
	}

	// Conditionally destroy resources unless SKIP_DESTROY env var is set to "true"
	if os.Getenv("SKIP_DESTROY") != "true" {
		defer terraform.DestroyContext(t, ctx, terraformOptions)
	} else {
		t.Log("SKIP_DESTROY is set; skipping terraform.Destroy() to preserve the environment.")
	}

	// Deploy resources
	terraform.InitAndApplyContext(t, ctx, terraformOptions)

	// Retrieve outputs
	host := fetchSensitiveOutput(t, terraformOptions, "host")
	clientCert := fetchSensitiveOutput(t, terraformOptions, "client_certificate")
	clientKey := fetchSensitiveOutput(t, terraformOptions, "client_key")
	clusterCACert := fetchSensitiveOutput(t, terraformOptions, "cluster_ca_certificate")
	resourceGroupName := terraform.OutputContext(t, ctx, terraformOptions, "resource_group_name")
	clusterName := terraform.OutputContext(t, ctx, terraformOptions, "cluster_name")

	// Validate that the output names match the expected patterns.
	rgPattern := regexp.MustCompile(`^test-[a-z0-9]{4}-cmkvs01$`)
	clusterPattern := regexp.MustCompile(`^test[a-z0-9]{4}cmkvs01$`)
	assert.Regexp(t, rgPattern, resourceGroupName, "Resource group name should match expected pattern")
	assert.Regexp(t, clusterPattern, clusterName, "Cluster name should match expected pattern")

	// Create a temporary directory for kubeconfig and certificate files
	tempDir, err := os.MkdirTemp("", "kubeconfig")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Write the AKS certificates to temporary files
	clientCertPath := filepath.Join(tempDir, "clientCert.pem")
	clientKeyPath := filepath.Join(tempDir, "clientKey.pem")
	clusterCAPath := filepath.Join(tempDir, "clusterCA.pem")

	err = os.WriteFile(clientCertPath, []byte(clientCert), 0644)
	assert.NoError(t, err)
	err = os.WriteFile(clientKeyPath, []byte(clientKey), 0644)
	assert.NoError(t, err)
	err = os.WriteFile(clusterCAPath, []byte(clusterCACert), 0644)
	assert.NoError(t, err)

	// Create kubeconfig file
	kubeconfigContent := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: cluster
  cluster:
    certificate-authority: %s
    server: %s
contexts:
- name: context
  context:
    cluster: cluster
    user: user
current-context: context
users:
- name: user
  user:
    client-certificate: %s
    client-key: %s
`, clusterCAPath, host, clientCertPath, clientKeyPath)

	kubeconfigPath := filepath.Join(tempDir, "kubeconfig.yaml")
	err = os.WriteFile(kubeconfigPath, []byte(kubeconfigContent), 0644)
	assert.NoError(t, err)

	// Default to 'monitoring' Namespace
	kubectlOptions := k8s.NewKubectlOptions("", kubeconfigPath, "monitoring")

	// Create a tunnel to the Prometheus service on tcp/9090
	tunnel := k8s.NewTunnel(kubectlOptions, k8s.ResourceTypeService, "prometheus-kube-prometheus-prometheus", 9090, 9090)
	defer tunnel.Close()
	tunnel.ForwardPort(t)

	waitForPrometheus(t, "certificate_sync_total", "a certificate sync", func(series []prometheusSeries) bool {
		for _, s := range series {
			if s.value() > 0 {
				return true
			}
		}
		return false
	})

	if upgrade {
		verifyUpgrade(t, terraformOptions, k8s.NewKubectlOptions("", kubeconfigPath, "cert-manager-key-vault-sync"))
	}

	verifyKeyVaultCertificates(t, terraformOptions)
}

// verifyUpgrade checks what the previous release synced, upgrades to the local chart and image, and checks the
// upgraded pods leave the existing Key Vault certificates untouched.
func verifyUpgrade(t *testing.T, options *terraform.Options, kubectlOptions *k8s.KubectlOptions) {
	ctx := t.Context()

	verifyKeyVaultCertificates(t, options)
	before := keyVaultSecretVersions(t, options)

	options.Vars["install_previous_release"] = false
	terraform.ApplyContext(t, ctx, options)
	k8s.RunKubectlContext(t, ctx, kubectlOptions, "rollout", "status", "deployment/cert-manager-key-vault-sync", "--timeout=5m")

	upgradedPods := map[string]bool{}
	for _, pod := range k8s.ListPodsContext(t, ctx, kubectlOptions, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=cert-manager-key-vault-sync"}) {
		if pod.DeletionTimestamp == nil {
			upgradedPods[pod.Name] = true
		}
	}
	require.NotEmpty(t, upgradedPods)

	waitForPrometheus(t, "sync_success_total", "a sync cycle on the upgraded pods", func(series []prometheusSeries) bool {
		for _, s := range series {
			if upgradedPods[s.Metric["pod"]] && s.value() > 0 {
				return true
			}
		}
		return false
	})

	imports, err := queryPrometheus("certificate_sync_total")
	require.NoError(t, err)
	for _, s := range imports {
		assert.False(t, upgradedPods[s.Metric["pod"]] && s.value() > 0, "upgraded pod %s should not import %s again", s.Metric["pod"], s.Metric["certificate"])
	}
	assert.Equal(t, before, keyVaultSecretVersions(t, options), "upgrading should not create new Key Vault certificate versions")
}

type prometheusSeries struct {
	Metric map[string]string `json:"metric"`
	Value  []any             `json:"value"`
}

func (s prometheusSeries) value() float64 {
	if len(s.Value) < 2 {
		return 0
	}
	text, _ := s.Value[1].(string)
	value, _ := strconv.ParseFloat(text, 64)
	return value
}

func queryPrometheus(query string) ([]prometheusSeries, error) {
	resp, err := http.Get("http://localhost:9090/api/v1/query?query=" + url.QueryEscape(query))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Data struct {
			Result []prometheusSeries `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result.Data.Result, nil
}

// waitForPrometheus polls a Prometheus query until done returns true, failing the test after five minutes.
func waitForPrometheus(t *testing.T, query, description string, done func([]prometheusSeries) bool) {
	deadline := time.Now().Add(5 * time.Minute)
	for i := 1; ; i++ {
		series, err := queryPrometheus(query)
		if err == nil && done(series) {
			t.Logf("Attempt %d: Found %s", i, description)
			return
		}
		if time.Now().Add(10 * time.Second).After(deadline) {
			t.Fatalf("Timed out waiting for %s. Last result of %s: %v, error: %v", description, query, series, err)
		}
		t.Logf("Attempt %d: Waiting for %s. Result of %s: %v, error: %v", i, description, query, series, err)
		time.Sleep(10 * time.Second)
	}
}

func syncedCertificates(t *testing.T, options *terraform.Options) (string, []syncedCertificate) {
	var certificates []syncedCertificate
	options.Logger = logger.Discard
	terraform.OutputStructContext(t, t.Context(), options, "certificates", &certificates)
	options.Logger = nil
	require.NotEmpty(t, certificates)
	return terraform.OutputContext(t, t.Context(), options, "key_vault_name"), certificates
}

// keyVaultSecretVersions returns the current secret version ID of each synced certificate.
func keyVaultSecretVersions(t *testing.T, options *terraform.Options) map[string]string {
	keyVaultName, certificates := syncedCertificates(t, options)
	deadline := time.Now().Add(5 * time.Minute)
	versions := map[string]string{}
	for _, certificate := range certificates {
		versions[certificate.Name] = readKeyVaultSecret(t, keyVaultName, certificate.Name, "id", deadline)
	}
	return versions
}

// verifyKeyVaultCertificates downloads each synced certificate the way App Gateway and other Key Vault
// consumers read it, and checks it opens without a password and holds the original key, certificate and CA.
func verifyKeyVaultCertificates(t *testing.T, options *terraform.Options) {
	keyVaultName, certificates := syncedCertificates(t, options)
	caCertificate := parseCertificate(t, terraform.OutputContext(t, t.Context(), options, "ca_certificate"))

	deadline := time.Now().Add(5 * time.Minute)
	for _, expected := range certificates {
		t.Run(expected.Name, func(t *testing.T) {
			pfx, err := base64.StdEncoding.DecodeString(readKeyVaultSecret(t, keyVaultName, expected.Name, "value", deadline))
			require.NoError(t, err)

			privateKey, leaf, chain, err := pkcs12.DecodeChain(pfx, "")
			require.NoError(t, err, "Key Vault should return the certificate as a PFX without a password")

			assert.Equal(t, parseCertificate(t, expected.Certificate).Raw, leaf.Raw, "certificate should match tls.crt")
			assert.Equal(t, publicKeyDER(t, parsePrivateKey(t, expected.PrivateKey)), publicKeyDER(t, privateKey), "private key should match tls.key")

			chainHasCA := false
			for _, c := range chain {
				chainHasCA = chainHasCA || string(c.Raw) == string(caCertificate.Raw)
			}
			assert.True(t, chainHasCA, "CA certificate from tls.crt should be in the chain")
		})
	}
}

// readKeyVaultSecret returns a field of a synced certificate's Key Vault secret, retrying until the deadline while the sync and RBAC catch up.
func readKeyVaultSecret(t *testing.T, keyVaultName, name, query string, deadline time.Time) string {
	var lastError string
	for i := 1; ; i++ {
		out, err := exec.Command("az", "keyvault", "secret", "show", "--vault-name", keyVaultName, "--name", name, "--query", query, "--output", "tsv").Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			lastError = strings.TrimSpace(string(exitErr.Stderr))
		} else {
			lastError = err.Error()
		}
		if time.Now().Add(10 * time.Second).After(deadline) {
			t.Fatalf("Could not read Key Vault secret %s: %s", name, lastError)
		}
		t.Logf("Attempt %d: Key Vault secret %s not readable yet: %s", i, name, lastError)
		time.Sleep(10 * time.Second)
	}
}

func parseCertificate(t *testing.T, pemData string) *x509.Certificate {
	block, _ := pem.Decode([]byte(pemData))
	require.NotNil(t, block, "expected a PEM certificate")
	certificate, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return certificate
}

func parsePrivateKey(t *testing.T, pemData string) any {
	block, _ := pem.Decode([]byte(pemData))
	require.NotNil(t, block, "expected a PEM private key")
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	require.NoError(t, err)
	return key
}

func publicKeyDER(t *testing.T, privateKey any) []byte {
	signer, ok := privateKey.(crypto.Signer)
	require.True(t, ok, "private key should be a crypto.Signer")
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	require.NoError(t, err)
	return der
}
