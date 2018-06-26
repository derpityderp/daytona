# daytona

```
Usage of ./daytona:
  -address string
        (env: VAULT_ADDR) (default "https://vault.secure.car:8200")
  -auth-role string
        used with either auth method (env: ROLE_NAME)
  -iam-auth
        select AWS IAM vault auth as the vault authentication mechanism
  -iam-auth-mount string
        the vault mount where iam auth takes place (env: IAM_AUTH_MOUNT) (default "aws")
  -k8s-auth
        select kubernetes vault auth as the vault authentication mechanism (env: K8S_AUTH)
  -k8s-auth-mount string
        the vault mount where k8s auth takes place (env: K8S_AUTH_MOUNT) (default "kubernetes")
  -k8s-token-path string
        kubernetes service account jtw token path (env: K8S_TOKEN_PATH) (default "/var/run/secrets/kubernetes.io/serviceaccount/token")
  -renewal-interval int
        how often to check the token's ttl and potentially renew it (env: RENEWAL_INTERVAL) (default 300)
  -renewal-threshold int
        the threshold remaining in the vault token, in seconds, after which it should be renewed (default 43200)
  -secret-path string
        (env: SECRET_PATH)
  -token-path string
        file path where a token will be read from/written to (env: TOKEN_PATH) (default "~/.vault-token")
```