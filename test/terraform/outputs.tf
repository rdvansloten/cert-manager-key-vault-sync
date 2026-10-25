output "resource_group_name" {
  value = azurerm_resource_group.main.name
}

output "cluster_name" {
  value = azurerm_kubernetes_cluster.main.name
}

output "host" {
  value     = azurerm_kubernetes_cluster.main.kube_config.0.host
  sensitive = true
}

output "client_certificate" {
  value     = base64decode(azurerm_kubernetes_cluster.main.kube_config.0.client_certificate)
  sensitive = true
}

output "client_key" {
  value     = base64decode(azurerm_kubernetes_cluster.main.kube_config.0.client_key)
  sensitive = true
}

output "cluster_ca_certificate" {
  value     = base64decode(azurerm_kubernetes_cluster.main.kube_config.0.cluster_ca_certificate)
  sensitive = true
}

output "key_vault_name" {
  value = azurerm_key_vault.main.name
}

output "ca_certificate" {
  value = tls_self_signed_cert.ca.cert_pem
}

output "certificates" {
  value = [for i in range(var.certificate_amount) : {
    name        = kubernetes_secret_v1.main[i].metadata[0].name
    certificate = tls_locally_signed_cert.main[i].cert_pem
    private_key = tls_private_key.main[i].private_key_pem
  }]
  sensitive = true
}
