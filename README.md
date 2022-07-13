```sh
helm upgrade --install trivy-operator aqua/trivy-operator \
  --namespace trivy-system \
  --create-namespace \
  --values values.yaml \
  --version 0.1.3

# Apply new Policies
kubectl apply -k ./policy
```
