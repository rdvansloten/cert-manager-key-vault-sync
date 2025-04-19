variable "location" {
  description = "Azure region to deploy resources"
  type        = string
  default     = "westeurope"
}

variable "docker_registry" {
  description = "Docker registry to use."
  type        = string
  default     = "registry-1.docker.io"
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
  default     = "Yunikon B.V."
}

variable "kube_prometheus_stack_version" {
  description = "Version of the kube-prometheus-stack Helm chart to install."
  type        = string
  default     = "69.7.4"
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