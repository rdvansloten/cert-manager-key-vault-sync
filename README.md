# cert-manager-key-vault-sync

Kubernetes app that syncs [cert-manager](https://cert-manager.io) Secrets to Azure Key Vault. Originally created with the intention of getting LetsEncrypt certficates into Key Vault, but works with any certificate stored in a Kubernetes Secret.

[![Docker Image](https://github.com/rdvansloten/cert-manager-key-vault-sync/actions/workflows/build-push-image.yaml/badge.svg)](https://github.com/rdvansloten/cert-manager-key-vault-sync/actions/workflows/build-push-image.yaml) [![Helm Chart](https://github.com/rdvansloten/cert-manager-key-vault-sync/actions/workflows/build-push-helm-chart.yaml/badge.svg)](https://github.com/rdvansloten/cert-manager-key-vault-sync/actions/workflows/build-push-helm-chart.yaml)

## Features

- Supports Kubernetes Nodes running `linux/amd64`, `linux/arm64` (Apple M1, Linux)
- Synchronizes Kubernetes Secrets to Azure Key Vault Certificates
- Leverages passwordless authentication using [Workload Identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview)
- Certificate is automatically rotated when cert-manager triggers a renewal
- Supports duplicate certificates in multiple Kubernetes Namespaces (e.g. `*.your-domain.com` in multiple Namespaces)
- Runs in a lightweight Alpine container, using < 100 MiB of memory
- Includes a [Helm Chart](#helm-installation) for easy installation

## Requirements & Limitations

- Running [cert-manager](https://cert-manager.io) `~> v1` in your Azure Kubernetes cluster
- Only syncs Kubernetes Secrets to Key Vault *Certificates* (not to Key Vault *Secrets*)
- The included Helm chart only authenticates using [Workload Identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview)

## Helm Installation

If you're running an older version of Helm, `HELM_EXPERIMENTAL_OCI=1` needs to be set to support OCI charts.

```sh
export HELM_EXPERIMENTAL_OCI=1
helm upgrade --install cert-manager-key-vault-sync \
    oci://docker.io/rdvansloten/cert-manager-key-vault-sync \
    --values ./charts/cert-manager-key-vault-sync/values.yaml \
    --version "v0.2.1" \
    --namespace cert-manager-key-vault-sync --create-namespace
```

If you wish to use raw Kubernetes manifests instead, you may render the Helm template to plain YAML using the command below.

```sh
helm template cert-manager-key-vault-sync oci://docker.io/rdvansloten/cert-manager-key-vault-sync \
    --values ./charts/cert-manager-key-vault-sync/values.yaml > output.yaml
```

## Examples

For examples on building the image from scratch or prepping your Azure/Kubernetes environment, see [Examples](./EXAMPLES.md).

## Design

The synchronization process is a small Python3 application running on an Alpine image. It leverages OpenSSL to bundle the `.cer` and `.key` files, then uploads the resulting `.pfx` file to Azure Key Vault. cert-manager-key-vault-sync requires verbs `"get"`, `"list"`, `"watch"` on the `"secrets"` resource, as it needs to pull cert-manager-generated Secrets from all namespaces. It will only search for Secrets with the annotation `cert-manager.io/certificate-name` by default, though this can be changed.

The attached Service Account is connected to a Managed Identity in Azure, providing access to the Key Vault. The Managed Identity requires the `Key Vault Certificates Officer` role on the Key Vault, or a custom role with permissions to list, read, create and update Certificates and their metadata.

### Diagram

![A diagram of the synchronization](./attachments/cert-sync.jpg)

## Contributing

I'd love your input! I want to make contributing to this project as easy and transparent as possible, whether it's:

- Reporting [an issue](https://github.com/rdvansloten/cert-manager-key-vault-sync/issues/new?assignees=&labels=bug&template=bug_report.yml).
- Submitting [a fix](https://github.com/rdvansloten/cert-manager-key-vault-sync/compare).
- Proposing [new features](https://github.com/rdvansloten/cert-manager-key-vault-sync/issues/new?assignees=&labels=enhancement&template=feature_request.yml).
- Becoming a maintainer.
- Supporting my GitHub page:

[<img src="https://ko-fi.com/img/githubbutton_sm.svg" alt="ko-fi donation button" width="200px">](https://ko-fi.com/V7V0WI9MI)

### All changes happen through Pull Requests

Pull requests are the best way to propose changes. I actively welcome your Pull Requests:

1. Fork this repository and create your branch from `main`.
2. If you've added code that should be tested, add some test examples.
3. Update the documentation.
4. Submit that Pull Request!
