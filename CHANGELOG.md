# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
