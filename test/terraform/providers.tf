terraform {
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4"
    }
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3"
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
  registry_auth {
    address  = "registry-1.docker.io"
  }
}

provider "kubernetes" {
  host                   = azurerm_kubernetes_cluster.main.kube_config.0.host
  client_certificate     = base64decode(azurerm_kubernetes_cluster.main.kube_config.0.client_certificate)
  client_key             = base64decode(azurerm_kubernetes_cluster.main.kube_config.0.client_key)
  cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.main.kube_config.0.cluster_ca_certificate)
}