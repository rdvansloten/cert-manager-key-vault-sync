package test

import (
	"testing"
	"time"

	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)

func TestTerraformAzureAKS(t *testing.T) {
	t.Parallel()

	terraformOptions := &terraform.Options{
		// The path to where your Terraform code is located
		TerraformDir: "./terraform",

		// Variables to pass to our Terraform code using -var options
		Vars: map[string]interface{}{
			"resource_group_name": "cert-manager-kv-test",
			"location":            "westeurope",
			"cluster_name":        "cert-manager-kv-test",
			"acr_name":            "certmanagerkvtest",
			"node_count":          1,
		},

		// Retry up to 3 times, with 30 seconds between retries,
		// on known errors
		MaxRetries:         3,
		TimeBetweenRetries: 30 * time.Second,
	}

	// At the end of the test, run `terraform destroy` to clean up any resources that were created
	defer terraform.Destroy(t, terraformOptions)

	// Run `terraform init` and `terraform apply`
	terraform.InitAndApply(t, terraformOptions)

	// Run `terraform output` to get the values of output variables
	resourceGroupName := terraform.Output(t, terraformOptions, "resource_group_name")
	clusterName := terraform.Output(t, terraformOptions, "cluster_name")
	acrLoginServer := terraform.Output(t, terraformOptions, "acr_login_server")

	// Verify that the resources were created with the expected names
	assert.Equal(t, "cert-manager-kv-test", resourceGroupName)
	assert.Equal(t, "cert-manager-kv-test", clusterName)
	assert.Contains(t, acrLoginServer, "certmanagerkvtest.azurecr.io")
}
