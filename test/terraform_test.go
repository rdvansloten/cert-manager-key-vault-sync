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

// fetchSensitiveOutput suppresses logging of sensitive outputs
func fetchSensitiveOutput(t *testing.T, options *terraform.Options, name string) string {
	defer func() {
		options.Logger = nil
	}()
	options.Logger = logger.Discard
	return terraform.Output(t, options, name)
}

func TestTerraformAzureAKS(t *testing.T) {
	t.Parallel()

	// Read any required Docker auth environment variables
	dockerUsername := os.Getenv("DOCKER_REGISTRY_USER")
	dockerPassword := os.Getenv("DOCKER_REGISTRY_PASS")

	terraformOptions := &terraform.Options{
		// Terraform folder
		TerraformDir: "./terraform",

		// Pass Terraform variables
		Vars: map[string]interface{}{},

		// Pass Docker auth environment variables to Terraform's shell environment
		EnvVars: map[string]string{
			"DOCKER_REGISTRY_USER": dockerUsername,
			"DOCKER_REGISTRY_PASS": dockerPassword,
		},

		// Retry settings for Terraform apply/destroy
		MaxRetries:         3,
		TimeBetweenRetries: 30 * time.Second,
	}
	// Destroy resources after testing
	defer terraform.Destroy(t, terraformOptions)

	// Deploy resources
	terraform.InitAndApply(t, terraformOptions)

	// Retrieve outputs
	host := fetchSensitiveOutput(t, terraformOptions, "host")
	clientCert := fetchSensitiveOutput(t, terraformOptions, "client_certificate")
	clientKey := fetchSensitiveOutput(t, terraformOptions, "client_key")
	clusterCACert := fetchSensitiveOutput(t, terraformOptions, "cluster_ca_certificate")
	resourceGroupName := terraform.Output(t, terraformOptions, "resource_group_name")
	clusterName := terraform.Output(t, terraformOptions, "cluster_name")

	// Validate that the output names match the expected patterns.
	rgPattern := regexp.MustCompile(`^test-[a-z0-9]{4}-cmkvs01$`)
	clusterPattern := regexp.MustCompile(`^test[a-z0-9]{4}cmkvs01$`)
	assert.Regexp(t, rgPattern, resourceGroupName, "Resource group name should match expected pattern")
	assert.Regexp(t, clusterPattern, clusterName, "Cluster name should match expected pattern")

	// Create a temporary directory for  kubeconfig and certificate files
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

	// Prometheus query URL for 'certificate_sync_total'
	url := fmt.Sprintf("http://localhost:%d/api/v1/query?query=certificate_sync_total", 9090)

	// Retrieve Prometheus metrics
	var result map[string]interface{}
	var resp *http.Response
	var lastResponseJSON string
	foundMetric := false
	maxRetries := 25

	for i := 0; i < maxRetries; i++ {
		resp, err = http.Get(url)
		if err != nil {
			t.Logf("Attempt %d: Error making HTTP request: %v", i+1, err)
		} else if resp.StatusCode != http.StatusOK {
			t.Logf("Attempt %d: Received non-OK status code: %d", i+1, resp.StatusCode)
			resp.Body.Close()
		} else {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()

			if readErr != nil {
				t.Logf("Attempt %d: Error reading response body: %v", i+1, readErr)
			} else {
				lastResponseJSON = string(body)
				t.Logf("Attempt %d: Prometheus response: %s", i+1, lastResponseJSON)
				err = json.Unmarshal(body, &result)
				if err != nil {
					t.Logf("Attempt %d: Error unmarshalling JSON: %v", i+1, err)
				} else {
					status, ok := result["status"].(string)
					if ok && status == "success" {
						data, ok := result["data"].(map[string]interface{})
						if ok {
							resultArray, ok := data["result"].([]interface{})
							if ok && len(resultArray) > 0 {
								firstResult, ok := resultArray[0].(map[string]interface{})
								if ok {
									valueField, ok := firstResult["value"].([]interface{})
									if ok && len(valueField) >= 2 && valueField[1] == "1" {
										foundMetric = true
										t.Logf("Attempt %d: Found metric with value 1", i+1)
										break
									} else {
										t.Logf("Attempt %d: Metric value not equal to 1", i+1)
									}
								} else {
									t.Logf("Attempt %d: Unexpected format for result element", i+1)
								}
							} else {
								t.Logf("Attempt %d: No results found in Prometheus response", i+1)
							}
						} else {
							t.Logf("Attempt %d: Data field missing or in unexpected format", i+1)
						}
					} else {
						t.Logf("Attempt %d: Prometheus query unsuccessful, status: %v", i+1, result["status"])
					}
				}
			}
		}
		time.Sleep(10 * time.Second)
	}
	t.Logf("Final Prometheus response: %s", lastResponseJSON)
	assert.True(t, foundMetric, fmt.Sprintf("Expected metric 'certificate_sync_total' to return a value of 1. Last response: %s", lastResponseJSON))
}
