package test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/gruntwork-io/terratest/modules/k8s"
	"github.com/gruntwork-io/terratest/modules/logger"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)

// fetchSensitiveOutput suppresses logging of sensitive outputs.
func fetchSensitiveOutput(t *testing.T, options *terraform.Options, name string) string {
	defer func() {
		options.Logger = nil
	}()
	options.Logger = logger.Discard
	return terraform.Output(t, options, name)
}

func TestTerraformAzureAKS(t *testing.T) {
	t.Parallel()

	// Read any required Docker auth environment variables.
	dockerUsername := os.Getenv("DOCKER_REGISTRY_USER")
	dockerPassword := os.Getenv("DOCKER_REGISTRY_PASS")

	terraformOptions := &terraform.Options{
		// Path to your Terraform code.
		TerraformDir: "./terraform",

		// Terraform variables (if any).
		Vars: map[string]interface{}{},

		// Pass Docker auth environment variables to Terraform.
		EnvVars: map[string]string{
			"DOCKER_REGISTRY_USER": dockerUsername,
			"DOCKER_REGISTRY_PASS": dockerPassword,
		},

		// Retry settings.
		MaxRetries:         3,
		TimeBetweenRetries: 30 * time.Second,
	}
	// Clean up resources at the end.
	defer terraform.Destroy(t, terraformOptions)

	// Deploy resources.
	terraform.InitAndApply(t, terraformOptions)

	// Retrieve outputs for resource names.
	resourceGroupName := terraform.Output(t, terraformOptions, "resource_group_name")
	clusterName := terraform.Output(t, terraformOptions, "cluster_name")

	// Validate that the output names match the expected patterns.
	rgPattern := regexp.MustCompile(`^test-[a-z0-9]{4}-cmkvs01$`)
	clusterPattern := regexp.MustCompile(`^test[a-z0-9]{4}cmkvs01$`)
	assert.Regexp(t, rgPattern, resourceGroupName, "Resource group name should match expected pattern")
	assert.Regexp(t, clusterPattern, clusterName, "Cluster name should match expected pattern")

	// Retrieve Kubernetes connection outputs using fetchSensitiveOutput to suppress logging.
	host := fetchSensitiveOutput(t, terraformOptions, "host")
	clientCert := fetchSensitiveOutput(t, terraformOptions, "client_certificate")
	clientKey := fetchSensitiveOutput(t, terraformOptions, "client_key")
	clusterCACert := fetchSensitiveOutput(t, terraformOptions, "cluster_ca_certificate")

	// Create a temporary directory for our kubeconfig and certificate files.
	tempDir, err := os.MkdirTemp("", "kubeconfig")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Write the Kubernetes certificates to temporary files.
	clientCertPath := filepath.Join(tempDir, "clientCert.pem")
	clientKeyPath := filepath.Join(tempDir, "clientKey.pem")
	clusterCAPath := filepath.Join(tempDir, "clusterCA.pem")

	err = os.WriteFile(clientCertPath, []byte(clientCert), 0644)
	assert.NoError(t, err)
	err = os.WriteFile(clientKeyPath, []byte(clientKey), 0644)
	assert.NoError(t, err)
	err = os.WriteFile(clusterCAPath, []byte(clusterCACert), 0644)
	assert.NoError(t, err)

	// Create a kubeconfig file that uses the above certificate files.
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

	// Create KubectlOptions using our generated kubeconfig.
	// We are targeting the "monitoring" namespace where Prometheus is deployed.
	kubectlOptions := k8s.NewKubectlOptions("", kubeconfigPath, "monitoring")

	// Create a tunnel to the Prometheus service.
	// Adjust the service name if needed.
	tunnel := k8s.NewTunnel(kubectlOptions, k8s.ResourceTypeService, "prometheus-kube-prometheus-prometheus", 9090, 9090)
	defer tunnel.Close()
	tunnel.ForwardPort(t)

	// Build the Prometheus query URL for "certificate_sync_total".
	url := fmt.Sprintf("http://localhost:%d/api/v1/query?query=certificate_sync_total", 9090)

	// Retry reading the Prometheus URL up to 25 times until we see the metric with a value of "1".
	var result map[string]interface{}
	var resp *http.Response
	var lastResponseJSON string
	foundMetric := false
	maxRetries := 25
	for i := 0; i < maxRetries; i++ {
		resp, err = http.Get(url)
		if err == nil && resp.StatusCode == 200 {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr == nil {
				lastResponseJSON = string(body)
				t.Logf("Attempt %d: Prometheus response: %s", i+1, lastResponseJSON)
				err = json.Unmarshal(body, &result)
				if err == nil {
					status, ok := result["status"].(string)
					if ok && status == "success" {
						data, ok := result["data"].(map[string]interface{})
						if ok {
							resultArray, ok := data["result"].([]interface{})
							if ok && len(resultArray) > 0 {
								// Check the value from the first result.
								firstResult, ok := resultArray[0].(map[string]interface{})
								if ok {
									valueField, ok := firstResult["value"].([]interface{})
									if ok && len(valueField) >= 2 && valueField[1] == "1" {
										foundMetric = true
										break
									}
								}
							}
						}
					}
				}
			}
		}
		time.Sleep(10 * time.Second)
	}
	t.Logf("Final Prometheus response: %s", lastResponseJSON)
	assert.True(t, foundMetric, "Expected certificate_sync_total to eventually return a value of 1")
}
