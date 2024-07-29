# cert-manager-key-vault-sync
Kubernetes app that syncs cert-manager Secrets to Azure Key Vault.

## Example

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

## Docker Build

```
docker buildx build . \
    --tag docker.io/rdvansloten/cert-manager-key-vault-sync:latest \
    --platform linux/amd64 \
    --pull

docker push docker.io/rdvansloten/cert-manager-key-vault-sync:latest
```

## Helm Installation

```
export HELM_EXPERIMENTAL_OCI=1
helm upgrade --install cert-manager-key-vault-sync \
    oci://registry-1.docker.io/rdvansloten/cert-manager-key-vault-sync \
    --values ./charts/cert-manager-key-vault-sync/values.yaml \
    --namespace cert-manager-key-vault-sync --create-namespace
```