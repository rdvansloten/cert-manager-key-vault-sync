output "resource_group_name" {
  value = azurerm_resource_group.main.name
}

output "cluster_name" {
  value = azurerm_kubernetes_cluster.main.name
}

output "host" {
  value = azurerm_kubernetes_cluster.main.kube_config.0.host
  sensitive = true
}

output "client_certificate" {
  value = base64decode(azurerm_kubernetes_cluster.main.kube_config.0.client_certificate)
  sensitive = true
}

output "client_key" {
  value = base64decode(azurerm_kubernetes_cluster.main.kube_config.0.client_key)
  sensitive = true
}

output "cluster_ca_certificate" {
  value = base64decode(azurerm_kubernetes_cluster.main.kube_config.0.cluster_ca_certificate)
  sensitive = true
}