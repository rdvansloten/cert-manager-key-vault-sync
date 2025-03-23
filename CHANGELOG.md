# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.2.0] - 2025-03-16

### Added

- `kopf` to enable high availability
- `ruff` for linting
- `terratest` tests
- `release: prometheus` label to ServiceMonitor to work with vanilla `kube_prometheus_stack`
- `mise` for package installations
- Leader election for multi-pod deployments

### Changed

- Tests now use terratest + Terraform instead of GitHub Workflows + Azure CLI
- Updated documentation in wiki
- Comments and formatting due to linting
- Switched to `uv` from `pip`
- Set default replicas to `3` from `1`

## [v1.1.0] - 2025-03-13

### Added

- Prometheus metrics endpoint

## [v1.0.0] - 2025-03-13

### Added

- Authentication using Service Principal

### Changed

- Moved `annotation`, `useNamespaces` and `checkInterval` under the key `certificates`

## [v0.2.0] - 2025-01-12

### Added

- Version check of the application at startup, and hourly afterwards. This log can be used for alerting in your log processor of choice. Can be opted out of using `versionCheck.enabled: false` in the Helm chart
- Packages `requests`, `packaging` and `threading`

### Removed

- `pyyaml` requirement, this is now unused after several changes

### Changed

- Upgraded to Python `3.13` from `3.12.4`
- Upgraded to alphine `3.21` from `unconstrained`
- Tests in GitHub Workflow [test-helm-chart.yaml](./.github/workflows/test-helm-chart.yaml) to check for Pod crashing
- Bumped package `azure-identity` package to `1.*` from `1.17.1`
- Bumped package `azure-keyvault-certificates` `4.*` from `4.8.0`
- Bumped package `kubernetes` to `30.*` from `30.10.0`
- Helm Chart updated to `v0.3.0` from `v0.2.2`

### Fixed

- `sync_k8s_secrets_to_key_vault()` has been rewritten to prevent memory leaks when processing increasing amounts of certificates. Can now process 1000-2000 certificates and stay under 128MiB usage
- Set `runs-on: ubuntu-22.04` in GitHub Workflows from `runs-on: latest` due to unavailable package providers during testing

## [v0.1.1] - 2024-09-21

### Removed

- Env variable for managed identity in `main.py`, this is auto-loaded now ([#6](https://github.com/rdvansloten/cert-manager-key-vault-sync/issues/6))
- Env variable for managed identity in `charts/cert-manager-key-vault-sync/templates/deployment.yaml`, this is auto-loaded in `main.py` ([#6](https://github.com/rdvansloten/cert-manager-key-vault-sync/issues/6))

### Changed

- Prefixed Helm version with `v` to match app version
- Adjusted `build-push-image.yaml` to read app version from `Chart.yaml`

### Fixed

- Lowercase `as` to uppercase `AS` in `./Dockerfile` to solve `WARN: FromAsCasing: 'as' and 'FROM' keywords' casing do not match (line 1)`
- Duplicate `arm64` request to solve `Duplicate platform result requested "linux/arm64"`

## [v0.1.0] - 2024-09-07

### Added

- Tests on an ephemeral AKS cluster, Key Vault and Managed Identity
- Documentation to render the Helm chart as Kubernetes manifests ([#3](https://github.com/rdvansloten/cert-manager-key-vault-sync/issues/3))
- A `CHANGELOG.md` file
- Support for `linux/arm64` (MacOS M1, Linux)

### Fixed

- Ability to upload duplicate Secret names from multiple namespaces using `useNamespaces=true` in `values.yaml`

### Changed

- Bumped the Python pyyaml package to `6.0.2` from `6.0.1`
- Bumped the Helm chart to `0.2.0`
- Renamed the release name from `cert-sync` to `cert-manager-key-vault-sync` in the Helm chart
