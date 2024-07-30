# cert-manager-key-vault-sync
Kubernetes app that syncs cert-manager Secrets to Azure Key Vault.

[![Docker Image](https://github.com/rdvansloten/cert-manager-key-vault-sync/actions/workflows/build-push-image.yaml/badge.svg)](https://github.com/rdvansloten/cert-manager-key-vault-sync/actions/workflows/build-push-image.yaml) [![Helm Chart](https://github.com/rdvansloten/cert-manager-key-vault-sync/actions/workflows/build-push-helm-chart.yaml/badge.svg)](https://github.com/rdvansloten/cert-manager-key-vault-sync/actions/workflows/build-push-helm-chart.yaml)

## Requirements & Limitations

- Running [cert-manager](https://cert-manager.io) `~> v1` in your Azure Kubernetes cluster
- Only syncs Kubernetes Secrets to Key Vault *Certificates* (not to Key Vault *Secrets*)
- Currently, the included Helm chart authenticates using [Workload Identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview)

## Design

The synchronization process is a small Python3 application running on an Alpine image. It leverages OpenSSL to bundle the `.cer` and `.key` files, then uploads the resulting `.pfx` file to Azure Key Vault. cert-manager-key-vault-sync requires verbs `"get"`, `"list"`, `"watch"` on the `"secrets"` resource, as it needs to pull cert-manager-generated Secrets from all namespaces. It will only search for Secrets with the annotation `cert-manager.io/certificate-name` by default, though this can be changed.

The attached Service Account is connected to a Managed Identity in Azure, providing access to the Key Vault. The Managed Identity requires the `Key Vault Certificates Officer` role on the Key Vault, or a custom role with permissions to list, read, create and update Certificates and their metadata.
  
![A diagram of the synchronization](./attachments/cert-sync.jpg)

## Examples

### Creating an Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: demo
  namespace: demo
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-staging
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - demo.yourdomain.com
      secretName: demo-yourdomain-com
  rules:
    - host: demo.yourdomain.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: demo
                port:
                  number: 80
```

### Creating a Managed Identity with Federation

```sh
AKS_NAME="your-aks-cluster"
AKS_RESOURCE_GROUP="your-aks-cluster-resource-group"
NAMESPACE="cert-manager-key-vault-sync"
RESOURCE_GROUP="some-resource-group"
APP_NAME="cert-manager-key-vault-sync"
OIDC_URL=$(az aks show --name $AKS_NAME --resource-group $AKS_RESOURCE_GROUP --query "oidcIssuerProfile.issuerUrl" -o tsv)

az identity create \
  --resource-group $RESOURCE_GROUP \
  --name $APP_NAME

az identity federated-credential create \
  --name $APP_NAME \
  --identity-name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --issuer $OIDC_URL \
  --subject "system:serviceaccount:$NAMESPACE:$APP_NAME" \
  --audiences api://AzureADTokenExchange
```

## Docker Build

```
docker buildx build . \
    --tag cert-manager-key-vault-sync:latest \
    --platform linux/amd64 \
    --pull
```

## Helm Installation

If you're running an older version of Helm, `HELM_EXPERIMENTAL_OCI=1` needs to be set to support OCI charts.

```
export HELM_EXPERIMENTAL_OCI=1
helm upgrade --install cert-manager-key-vault-sync \
    oci://docker.io/rdvansloten/cert-manager-key-vault-sync \
    --values ./charts/cert-manager-key-vault-sync/values.yaml \
    --namespace cert-manager-key-vault-sync --create-namespace
```

## Contributing to [cert-manager-key-vault-sync](https://github.com/rdvansloten/cert-manager-key-vault-sync)

I'd love your input! I want to make contributing to this project as easy and transparent as possible, whether it's:

-   Reporting [an issue](https://github.com/rdvansloten/cert-manager-key-vault-sync/issues/new?assignees=&labels=bug&template=bug_report.yml).
-   [Discussing](https://github.com/rdvansloten/cert-manager-key-vault-sync/discussions) the current state of the code.
-   Submitting [a fix](https://github.com/rdvansloten/cert-manager-key-vault-sync/compare).
-   Proposing [new features](https://github.com/rdvansloten/cert-manager-key-vault-sync/issues/new?assignees=&labels=enhancement&template=feature_request.yml).
-   Becoming a maintainer.

**All changes happen through Pull Requests**

Pull requests are the best way to propose changes. I actively welcome your Pull Requests:

1.  Fork this repository and create your branch from `main`.
2.  If you've added code that should be tested, add some test examples.
3.  Update the documentation.
4.  Submit that Pull Request!