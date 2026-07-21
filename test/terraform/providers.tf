terraform {
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      # Needs 4.65+ for user_assigned_identity_id on azurerm_federated_identity_credential;
      # ~> 4 tracks the latest v4.
      version = "~> 4"
    }
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 4"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4"
    }
  }
}

provider "helm" {
  kubernetes {
    host                   = azurerm_kubernetes_cluster.main.kube_config.0.host
    client_certificate     = base64decode(azurerm_kubernetes_cluster.main.kube_config.0.client_certificate)
    client_key             = base64decode(azurerm_kubernetes_cluster.main.kube_config.0.client_key)
    cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.main.kube_config.0.cluster_ca_certificate)
  }
}
provider "azurerm" {
  features {}
  subscription_id = "865f86e6-0a9a-4c2f-8742-ce207e509dad"
}

provider "docker" {
  host = "unix:///var/run/docker.sock"

  # Authenticate with explicit credentials from DOCKER_REGISTRY_USER /
  # DOCKER_REGISTRY_PASS (the provider reads these env vars natively). This
  # avoids the credential-helper lookup, which v4 broke for Docker Hub by
  # normalising the address to registry-1.docker.io (no keychain entry) instead
  # of index.docker.io. The dev Taskfile fills these from your Docker login; CI
  # sets them too. Two blocks cover both Hub address forms the provider may use.
  registry_auth {
    address = "index.docker.io"
  }
  registry_auth {
    address = "registry-1.docker.io"
  }
}

provider "kubernetes" {
  host                   = azurerm_kubernetes_cluster.main.kube_config.0.host
  client_certificate     = base64decode(azurerm_kubernetes_cluster.main.kube_config.0.client_certificate)
  client_key             = base64decode(azurerm_kubernetes_cluster.main.kube_config.0.client_key)
  cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.main.kube_config.0.cluster_ca_certificate)
}