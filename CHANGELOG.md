# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2024-09-07

### Added

- Tests on an ephemeral AKS cluster, Key Vault and Managed Identity
- Documentation to render the Helm chart as Kubernetes manifests ([#3](https://github.com/rdvansloten/cert-manager-key-vault-sync/issues/3))
- A `CHANGELOG.md` file

### Fixed

- Ability to upload duplicate Secret names from multiple namespaces using `useNamespaces=true` in `values.yaml`

### Changed

- Bumped the Python pyyaml package to `6.0.2` from `6.0.1`
- Bumped the Helm chart to `0.2.0`
- Renamed the release name from `cert-sync` to `cert-manager-key-vault-sync` in the Helm chart
