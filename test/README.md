# Test Environment for cert-manager-key-vault-sync

This directory contains OpenTofu configurations and Terratest files to set up a test environment for the cert-manager-key-vault-sync project. The environment includes:

- Azure Kubernetes Service (AKS) cluster with Managed Prometheus
- Azure Key Vault
- Azure Container Registry (ACR)
- Necessary IAM roles and permissions

## Prerequisites

- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli#install) (`>= 2.x`)
- [OpenTofu](https://opentofu.org/docs/intro/install/) (`>= 1.13`)
- [Go](https://go.dev/doc/install) (`>= 1.26`)
- [Mise](https://mise.jdx.dev/getting-started.html#getting-started) (`>= 2025.x`)
- [Docker](https://docs.docker.com/desktop/) (`>= 27.x`)

## Setup

1. Login to Azure CLI:

```bash
az login
```

2. Initialize packages:

```bash
mise install
```

3. Install Go dependencies:

```bash
go mod tidy
```

## Running Tests

To run the Terratest suite:

```bash
go test -v -timeout 30m
```

This will:

1. Create all required Azure resources
2. Verify the infrastructure is correctly configured
3. Clean up all resources after the test

## Manual Testing

If you want to manually deploy the infrastructure from local:

```bash
mise install
cd ./test
export DOCKER_REGISTRY_USER="Your username/email here"
export DOCKER_REGISTRY_PASS="Your password/API token here"
go test -v
```

You can set `export SKIP_DESTROY=true` to prevent resources from being destroyed, in case you wish to debug inside Kubernetes.

To get the AKS credentials:

```bash
az aks get-credentials --resource-group cert-manager-kv-test --name cert-manager-kv-test
```

To clean up:

```bash
cd ./terraform
tofu destroy
```

## Configuration

You can modify the following variables in `terraform/variables.tf`:

- `resource_group_name`: Name of the Azure resource group
- `location`: Azure region to deploy resources
- `cluster_name`: Name of the AKS cluster
- `acr_name`: Name of the Azure Container Registry
- `node_count`: Number of nodes in the AKS cluster
