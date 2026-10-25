variable "auto_cleanup" {
  description = "Tag the resource group so the nightly cleanup workflow deletes it when it is left behind."
  type        = bool
  default     = false
}

variable "install_previous_release" {
  description = "Install the previous published chart and image instead of the local chart and test image."
  type        = bool
  default     = false
}

variable "previous_chart_version" {
  description = "Published chart version that the upgrade test starts from."
  type        = string
  # renovate: datasource=docker depName=rdvansloten/cert-manager-key-vault-sync-chart versioning=semver
  default = "v1.4.1"
}

variable "location" {
  description = "Azure region to deploy resources"
  type        = string
  default     = "westeurope"
}

variable "docker_registry" {
  description = "Docker registry to use."
  type        = string
  default     = "index.docker.io"
}

variable "docker_repository" {
  description = "Docker repository to use."
  type        = string
  default     = "rdvansloten/cert-manager-key-vault-sync"
}

variable "certificate_name" {
  description = "Name of the certificate to create."
  type        = string
  default     = "test-cmkvs-rdvansloten-nl"
}

variable "certificate_domain" {
  description = "Parent domain name for the certificate."
  type        = string
  default     = "rdvansloten.nl"
}

variable "certificate_organization" {
  description = "Organization name for the certificate."
  type        = string
  default     = "Yunikon"
}

variable "kubernetes_version" {
  description = "Kubernetes minor version of the AKS cluster. AKS picks the latest patch."
  type        = string
  # renovate: datasource=endoflife-date depName=azure-kubernetes-service versioning=loose
  default = "1.36"
}

variable "kube_prometheus_stack_version" {
  description = "Version of the kube-prometheus-stack Helm chart to install."
  type        = string
  # renovate: datasource=helm depName=kube-prometheus-stack registryUrl=https://prometheus-community.github.io/helm-charts
  default = "92.13.1"
}

variable "kube_prometheus_stack_repository" {
  description = "Repository of the kube-prometheus-stack Helm chart to install."
  type        = string
  default     = "https://prometheus-community.github.io/helm-charts"
}

variable "certificate_amount" {
  description = "Amount of certificates to create."
  type        = number
  default     = 1
}

variable "config_file_content" {
  description = "Docker auth config file content."
  type        = string
  default     = "{\"auths\":{\"https://index.docker.io/v1/\":{},\"https://registry-1.docker.io/v1/\":{}},\"credsStore\":\"osxkeychain\"}"
}