# cert-manager-key-vault-sync

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

Ensure that this Managed Identity has Key Vault Certificates Officer on your Key Vault.

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

### Output

```sh
2024-07-30 10:59:03 - INFO - Initializing with Client ID: 0dc3b***
2024-07-30 10:59:03 - INFO - Initialized Azure Key Vault client using Key Vault 'kv-demo'.
2024-07-30 10:59:03 - INFO - Starting cert-manager-key-vault-sync process.
2024-07-30 10:59:03 - INFO - Connection to Kubernetes successful.
2024-07-30 10:59:03 - INFO - Detected Secrets:
2024-07-30 10:59:04 - INFO - - 'demo-sandbox-com' in namespace 'default'
2024-07-30 10:59:04 - INFO - - 'demo2-sandbox-com' in namespace 'default'
2024-07-30 10:59:04 - INFO - - 'grafana-sandbox-com' in namespace 'grafana'
2024-07-30 10:59:04 - INFO - Connection to Key Vault successful.
2024-07-30 11:09:06 - INFO - Key Vault Certificate 'demo2-sandbox-com' does not exist. Creating it.
2024-07-30 11:09:06 - INFO - Writing Secret demo2-sandbox-com from namespace 'default' to Key Vault 'kv-demo'.
2024-07-30 11:09:06 - INFO - PFX certificate 'demo2-sandbox-com' imported successfully.
```

## Docker Build

```sh
docker buildx build . \
    --tag cert-manager-key-vault-sync:latest \
    --platform linux/amd64 \
    --pull
```