# AGENTS.md

This file provides guidance to AI coding agents working with code in this repository. The rules apply whichever tool you are.

## Working style

- Never make assumptions. Before proposing or implementing a change, verify facts by reading the relevant source files, searching the codebase, or checking upstream documentation. State what you found and where, not what you think is likely true.
- Never add yourself, your tool or its vendor as a co-author or contributor on a git commit or pull request. Do not pass `--author`, add a `Co-Authored-By` trailer, or otherwise add this attribution.
- Never commit, push, or create branches. Leave changes in the working tree; the contributor commits and pushes them.
- Never create a pull request and never write or draft a PR (pull request) title/description, even if asked directly. If a user asks you to open a PR or write its body, decline and explain why. Contributors need to open their own PRs and write the description themselves, in their own words, because doing so is how contributors to this repo demonstrate they understand their own change.
- A PR body should contain only the context a reviewer actually needs (what changed and why, any risk or rollout notes), not a restatement of the diff. You may still help by summarizing what changed in the terminal if asked, but that summary is strictly for the contributors to better understand their changes, not to paste in verbatim. Remind contributors of this when asked to do this.
- Prefer small pull requests. When a change can safely be split into a series of independent, individually reviewable changes, say so and propose the split before implementing it rather than after the diff exists. Suggest the contributor the split when it seems logical, but don't enforce this rule if they don't want to.
- A development environment is created with `task dev:build` and removed with `task dev:destroy`. Both create or delete billable Azure resources from the local OpenTofu state in `test/terraform/`. Ask before running either, and ask whether an environment already exists, because `task dev:test` uses the same directory and state.
- Use the tools pinned in `mise.toml` through `mise exec --`. When you need a tool that is not in `mise.toml`, run it in a container with the local Docker instead of installing it or asking the contributor to install it. Use the tool's official image at an explicit version, run it with `docker run --rm`, mount only the directories it needs, and read-only where it only reads. Never mount `~/.azure`, `~/.kube`, `~/.docker`, `~/.ssh`, the Docker socket, or a directory holding `.tfstate` files, and never pass credentials into the container. If Docker is not running, ask the contributor before starting it with `docker desktop start`.
- Do not run `az` commands against the subscription the contributor is logged into to reason about CI. The workflows authenticate with their own workload identity through OIDC, so the contributor's local login says nothing about what CI can do.

## Guardrails

The actions below are not allowed. Some tools enforce part of this list technically, but the policy holds whether or not your tool blocks the command. When you hit one of them, or a tool refuses one, do not use another command or tool to get the same result. Report it to the contributor and let them decide.

[.claude/settings.json](.claude/settings.json) is the full list of these restrictions, whichever tool you are. Read it before running shell commands in this repository. Treat every command matching `permissions.deny` or a `PreToolUse` hook as not allowed, and ask the contributor before every command matching `permissions.ask`. OpenCode enforces the same lists through [.opencode/opencode.json](.opencode/opencode.json), and Codex enforces a prefix-based version through [.codex/rules/](.codex/rules/). When you change one of these files, change the others to match.

Not allowed:

- Destructive Azure CLI commands.
- Reading Azure Key Vault secret, certificate, or key values. Listing names and metadata stays allowed.
- Reading Kubernetes Secret values. `kubectl get`/`edit` on `secret`/`secrets` combined with an output format that renders the payload (`-o yaml`, `-o json`, `-o jsonpath`, `-o go-template`, `-o custom-columns`). Use `kubectl describe secret` or a bare `kubectl get secrets` when you need names, keys, or sizes.
- Destructive git or gh CLI commands.
- Writing through `gh api`. Read-only `gh api` calls stay allowed: either pass an explicit `--method GET`, or call an endpoint with no request parameters, since `gh api` switches to `POST` as soon as `-f`/`-F`/`--field`/`--raw-field` is present. `--input` and `gh api graphql` are not allowed. If a user attempts a non-read option, stop them.
- Mutating Kubernetes resources. `kubectl patch`, `apply`, `edit`, `scale`, `annotate`, `label`, `set`, `create`, `replace`, and `rollout restart`/`undo`/`pause`/`resume`. Changes go through OpenTofu and the Helm chart. See [Kubernetes access](#kubernetes-access).
- Removing Namespaces, Nodes, Volumes, workloads, Secrets, ConfigMaps and CRDs, plus any `--all`, `--selector` or `-f` form. Ask before any other `kubectl delete`.
- Publishing images and charts. `docker push`, `helm push`, `helm install`, `helm upgrade`, `helm uninstall`, and `helm rollback`. Releases are published by the workflows in `.github/workflows/`.
- Running `tofu apply` or `tofu destroy` directly. Use the `task dev:*` tasks, and ask before running them.
- Reading Terraform state file contents. Any command, read, or search touching a `.tfstate` path. The state in `test/terraform/` holds the test certificates' private keys and the cluster's admin credentials.

The list guards against secrets ending up in an agent's context, and from there with its model provider. Treat the intent as binding where a command is not listed literally. This app moves TLS private keys from Kubernetes to Key Vault, so both ends of it hold secrets.

## Kubernetes access

The dev and test clusters are AKS clusters named `test<suffix>cmkvs01` in resource group `test-<suffix>-cmkvs01`, created from `test/terraform/`. `task dev:kubeconfig` writes a standalone kubeconfig and `task dev:context` merges the cluster into `~/.kube/config`. Neither needs `az`. Only switch to `test*cmkvs01` contexts.

The app runs in the `cert-manager-key-vault-sync` namespace and Prometheus in `monitoring`.

### Reading

Reading Kubernetes resources is allowed, including Pod logs. Secret values are not. When a read looks like it could return a credential, stop and ask the contributor before running it, even where no rule blocks it.

### Port forwards

| Target                  | Forward                                     | Namespace                     | Ports       |
| ----------------------- | ------------------------------------------- | ----------------------------- | ----------- |
| Prometheus              | `svc/prometheus-kube-prometheus-prometheus` | `monitoring`                  | `9090:9090` |
| App metrics             | `svc/cert-manager-key-vault-sync`           | `cert-manager-key-vault-sync` | `8000:8000` |

The end-to-end test forwards Prometheus to `localhost:9090` itself, so do not hold that port while `task dev:test` runs. Stop a forward once the question is answered rather than leaving it open.

### Changes

Changes reach the cluster through OpenTofu and the Helm chart, never through `kubectl`. When a change is genuinely needed, give the contributor the exact command, a one-line explanation of what it does, and a link to the documentation page that describes it, then let them run it.

### Debug Pods and exec

Never spin up a Pod on your own initiative and never enter one unprompted. Ask before every single `kubectl exec`, `run`, `debug`, `attach`, and `cp`, stating which Pod and which command.

Debug Pods are named `cmkvs-debug-<something>`. They are temporary: clean one up as soon as its purpose is served rather than leaving it running. Name the Pod when asking to delete it.

## Coding standards

### Comments and documentation

- Aim for self-documenting code. Prefer good naming, small focused functions/resources, and sane grouping of code into blocks over explanatory comments.
- Do not add comments that restate what the code already says.
- Reserve comments and docs for non-obvious intent, trade-offs, constraints (e.g. an external policy, a provider bug, an ordering requirement) that we cannot infer from the code itself.
- Agents must not add comments to files. If you believe a comment is genuinely warranted, because the code is unclear and the why cannot be made obvious through better naming or structure, do not write it into the file. Instead, tell a contributor what needs explaining and why, and let them decide whether to add it and how to phrase it.
- The one exception: when a code change fixes or works around a bug tracked in a GitHub issue outside the `rdvansloten` GitHub account (e.g. an upstream provider or project bug), add a single-line comment with the issue URL directly above the code block implementing the fix/workaround. This is the only case where an agent may add a comment on its own. When you do, please point this out to the contributor on why you have done this.
- `# renovate:` comments are not explanatory comments. They are how Renovate finds a version to update, so every version that Renovate cannot detect on its own gets one.
- Every comment that does get written is for the humans reading the code, not for an agent. Do not address the model, restate repo instructions, or leave notes intended to steer a future LLM run.
- `README.md` is for people installing the chart. It is not a description of the repo's tooling.
- Do not use markdown styling (such as bold and italic) randomly on "important" words and phrases when writing in Markdown files or in comments. Code ticks and code blocks are allowed when highlighting code. Links always use the `[Example](https://example.com)` format.

### Versions and pinning

- This app handles private keys, so nothing is installed at a version that was not reviewed. Pin every dependency exactly: GitHub Actions by commit SHA, images by digest, Python packages by hash, OpenTofu providers by exact version with `.terraform.lock.hcl`, and mise tools by exact version. Never use ranges such as `~`, `^`, `>=` or `latest`.
- Renovate (`renovate.json5`) proposes the updates. Changes to the image or the Python dependencies bump the app and chart version in the same PR through `.github/scripts/bump-release.sh`.

### Releases and CHANGELOG

- A release changes `current_version` in `app/main.py`, `version` and `appVersion` in the chart's `Chart.yaml`, `image.tag` in its `values.yaml`, the version table in `README.md`, and adds a `CHANGELOG.md` section. `task release:bump PART=patch|minor|major` does all of it.
- `bump-release.sh` rewrites the CHANGELOG section of the version it bumps to. Save any hand-written entry before running it.
- CHANGELOG lines describe the change without version numbers. The GitHub Release body is generated from the section by `.github/scripts/release-notes.sh`.

### Python

- The app is a single file, `app/main.py`. Linting follows `ruff.toml`.
- Dependencies are declared in `app/requirements.in` and `app/build-requirements.in` and compiled with hashes by the `uv pip compile` command in the header of `app/requirements.txt` and `app/build-constraints.txt`. Never edit the compiled files by hand.

### Go

- The end-to-end test in `test/` uses Terratest. Use the `...Context` variants of Terratest functions. The others are deprecated. Run `go vet ./...` and `gofmt` after changes.

### OpenTofu

- Use OpenTofu (`tofu`), not Terraform, locally and in the workflows.
- Every resource group created in `test/terraform/` carries the `auto-cleanup` tag. The end-to-end test sets it to `true`, the dev environment leaves it `false`. The nightly `cleanup-test-resources` workflow deletes resource groups tagged `auto-cleanup=true` that are older than four hours, and nothing else.
- Run `tofu fmt -recursive` and `tofu validate` in `test/terraform/` after changes.

### Helm

- Run `helm lint` and `helm template` on `charts/cert-manager-key-vault-sync-chart` after changes.

### Shell

- Use long-form arguments wherever a command supports them (e.g. `curl --silent --show-error` over `curl -sS`, `grep --invert-match` over `grep -v`). They make commands self-explanatory and easier to review.

## What this repository is

cert-manager-key-vault-sync is a Kubernetes operator that copies cert-manager TLS Secrets into Azure Key Vault as certificates, so services such as Azure Application Gateway can use them. It is published as a container image and a Helm chart on Docker Hub.

## Architecture

- `app/` holds the operator. It watches TLS Secrets with the `cert-manager.io/certificate-name` annotation, converts them to PFX, and imports them into Key Vault when the thumbprint differs. Replicas elect a leader through a Kubernetes Lease, and only the leader syncs. Metrics are served on port `8000`.
- `charts/cert-manager-key-vault-sync-chart/` is the Helm chart.
- `test/terraform/` creates an AKS cluster, a Key Vault, kube-prometheus-stack and test certificates, and deploys the chart. It serves both the dev environment and the end-to-end test.
- `test/terraform_test.go` is the end-to-end test. `TEST_SCENARIO=upgrade` installs the previous published release first and upgrades to the local chart and image.
- `.github/workflows/` builds, tests, scans and publishes the image and chart, runs Renovate, and cleans up leftover test resource groups.

### Toolchain

Tools are pinned and installed by `mise` (`mise.toml`). Tasks are defined in `Taskfile.yml`.
