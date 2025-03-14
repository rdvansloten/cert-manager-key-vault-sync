resource "random_string" "main" {
  length  = 4
  special = false
  upper   = false
}

# Azure
resource "azurerm_resource_group" "main" {
  name     = "test-${random_string.main.result}-cmkvs01"
  location = var.location
}

resource "azurerm_kubernetes_cluster" "main" {
  name                      = "test${random_string.main.result}cmkvs01"
  location                  = azurerm_resource_group.main.location
  resource_group_name       = azurerm_resource_group.main.name
  dns_prefix                = "testcmkvs"
  oidc_issuer_enabled       = true
  workload_identity_enabled = true

  default_node_pool {
    name       = "system"
    node_count = 1
    vm_size    = "Standard_DS2_v2"
    upgrade_settings {
      drain_timeout_in_minutes      = 0
      max_surge                     = "50%"
      node_soak_duration_in_minutes = 0
    }
  }

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_role_assignment" "main" {
  for_each = {
    "AcrPull" = azurerm_kubernetes_cluster.main.kubelet_identity[0].object_id
    "AcrPush" = data.azurerm_client_config.current.object_id
  }
  principal_id         = each.value
  role_definition_name = each.key
  scope                = azurerm_container_registry.main.id
}

resource "azurerm_key_vault" "main" {
  name                          = "kvtest${random_string.main.result}cmkvs01"
  location                      = azurerm_resource_group.main.location
  resource_group_name           = azurerm_resource_group.main.name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  enable_rbac_authorization     = true
  public_network_access_enabled = true
}

resource "azurerm_container_registry" "main" {
  name                = "acrtest${random_string.main.result}cmkvs01"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Basic"
  admin_enabled       = true
}

resource "azurerm_user_assigned_identity" "main" {
  name                = "uai-test${random_string.main.result}cmkvs01"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
}

resource "azurerm_federated_identity_credential" "main" {
  name                = "test"
  resource_group_name = azurerm_resource_group.main.name
  audience            = ["api://AzureADTokenExchange"]
  issuer              = azurerm_kubernetes_cluster.main.oidc_issuer_url
  parent_id           = azurerm_user_assigned_identity.main.id
  subject             = "system:serviceaccount:cert-manager-key-vault-sync:cert-manager-key-vault-sync"
}

resource "azurerm_role_assignment" "cmkvs" {
  principal_id         = azurerm_user_assigned_identity.main.principal_id
  role_definition_name = "Key Vault Administrator"
  scope                = azurerm_key_vault.main.id
}

# Certificate
resource "tls_private_key" "main" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_self_signed_cert" "main" {
  private_key_pem = tls_private_key.main.private_key_pem

  subject {
    common_name  = "test.cmkvs.rdvansloten.nl"
    organization = "Yunikon B.V."
  }

  validity_period_hours = 1

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

resource "kubernetes_secret_v1" "main" {
  metadata {
    name = "test-cmkvs-rdvansloten-nl"
    annotations = {
      "cert-manager.io/certificate-name" = "test-cmkvs-rdvansloten-nl"
    }
  }

  data = {
    "tls.crt" = tls_self_signed_cert.main.cert_pem
    "tls.key" = tls_private_key.main.private_key_pem
    "ca.crt"  = ""
  }

  type = "kubernetes.io/tls"
}

# Helm
resource "helm_release" "prometheus" {
  name             = "prometheus"
  repository       = "https://prometheus-community.github.io/helm-charts"
  chart            = "kube-prometheus-stack"
  namespace        = "monitoring"
  create_namespace = true
  version          = "69.7.4"
}

resource "helm_release" "cert-manager-key-vault-sync" {
  name             = "cert-manager-key-vault-sync"
  chart            = "../../charts/cert-manager-key-vault-sync"
  namespace        = "cert-manager-key-vault-sync"
  create_namespace = true
  force_update     = true

  depends_on = [
    helm_release.prometheus,
    docker_registry_image.main,
    azurerm_role_assignment.main,
    tls_self_signed_cert.main
  ]

  set {
    name  = "image.repository"
    value = "${azurerm_container_registry.main.login_server}/cert-manager-key-vault-sync"
  }

  set {
    name  = "image.tag"
    value = "test-${random_string.main.result}"
  }

  set {
    name  = "azure.keyVaultName"
    value = azurerm_key_vault.main.name
  }

  set {
    name  = "azure.workloadIdentity.clientId"
    value = azurerm_user_assigned_identity.main.client_id
  }

  set {
    name  = "azure.workloadIdentity.subscriptionId"
    value = data.azurerm_client_config.current.subscription_id
  }

  set {
    name  = "azure.workloadIdentity.tenantId"
    value = data.azurerm_client_config.current.tenant_id
  }
}

# Docker
resource "docker_image" "main" {
  name = "${azurerm_container_registry.main.login_server}/cert-manager-key-vault-sync:test-${random_string.main.result}"
  build {
    context  = "../../"
    platform = "linux/amd64"
  }
}

resource "docker_registry_image" "main" {
  name          = docker_image.main.name
  keep_remotely = true
}