# cert-manager-key-vault-sync

> [!WARNING]  
> Due to an oversight when aligning versions, Helm Charts and Docker images were overwriting one another on the latest builds. This is now resolved by moving the Helm Charts to `docker.io/rdvansloten/cert-manager-key-vault-sync-chart`. Please update your install accordingly.

Kubernetes app that syncs [cert-manager](https://cert-manager.io) Secrets to Azure Key Vault.

| Component   | Version | Status                                                                                                                           |
| ----------- | ------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Helm Chart  | v1.2.1  | ![Helm Chart](https://github.com/rdvansloten/cert-manager-key-vault-sync/actions/workflows/build-push-helm-chart.yaml/badge.svg) |
| Application | v1.2.0  | ![Docker Image](https://github.com/rdvansloten/cert-manager-key-vault-sync/actions/workflows/build-push-image.yaml/badge.svg)    |

## Features

- Supports Kubernetes Nodes running `linux/amd64` (Intel, AMD), `linux/arm64` (Apple M1, ARM)
- Synchronizes Kubernetes Secrets to Azure Key Vault Certificates
- Allows for passwordless authentication using [Workload Identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview) or Service Principal with Client Secret
- Certificate is automatically rotated when cert-manager triggers a renewal
- Supports duplicate certificates in multiple Kubernetes Namespaces (e.g. `*.your-domain.com` in multiple Namespaces)
- Runs in a lightweight Alpine container, generally using < 128 MiB of memory
- Includes a [Helm Chart](#helm-installation) for easy installation

## Documentation

For complete documentation, see the [`wiki`](https://github.com/rdvansloten/cert-manager-key-vault-sync/wiki).

## Requirements & Limitations

- Running [cert-manager](https://cert-manager.io) `~> v1` in your Azure Kubernetes cluster
- Only syncs Kubernetes Secrets to Key Vault _Certificates_ (not to Key Vault _Secrets_)
- The included Helm chart only authenticates using [Workload Identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview) or Service Principal.

## Helm Installation

[Helm v3 or higher](https://helm.sh/docs/intro/install/#through-package-managers) is recommended for use with this Helm Chart.

```sh
export HELM_EXPERIMENTAL_OCI=1
helm upgrade --install cert-manager-key-vault-sync \
    oci://docker.io/rdvansloten/cert-manager-key-vault-sync-chart \
    --values ./charts/cert-manager-key-vault-sync-chart/values.yaml \
    --version v1.2.1 \
    --namespace cert-manager-key-vault-sync --create-namespace
```

If you wish to use raw Kubernetes manifests instead, you may render the Helm template to plain YAML using the command below.

```sh
helm template cert-manager-key-vault-sync oci://docker.io/rdvansloten/cert-manager-key-vault-sync-chart --version v1.2.1 \
    --values ./charts/cert-manager-key-vault-sync-chart/values.yaml > output.yaml
```

## Contributing

I'd love your input! I want to make contributing to this project as easy and transparent as possible, whether it's:

- Reporting [an issue](https://github.com/rdvansloten/cert-manager-key-vault-sync/issues/new?assignees=&labels=bug&template=bug_report.yml).
- Submitting [a fix](https://github.com/rdvansloten/cert-manager-key-vault-sync/compare).
- Proposing [new features](https://github.com/rdvansloten/cert-manager-key-vault-sync/issues/new?assignees=&labels=enhancement&template=feature_request.yml).
- Becoming a maintainer.
- Supporting my GitHub page through [GitHub Sponsors](https://github.com/sponsors/rdvansloten) or [ko-fi](https://ko-fi.com/V7V0WI9MI).

### All changes happen through Pull Requests

Pull requests are the best way to propose changes. I actively welcome your Pull Requests:

1. Fork this repository and create your branch from `main`.
2. If you've added code that should be tested, add some test examples.
3. Update the documentation.
4. Submit that Pull Request!
