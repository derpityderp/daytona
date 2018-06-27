# DAYTONA

This is intended to be a lighter, alternate implementation of the vault client CLI, but for servers and containers. Its core features are the abilty to automate authentication, fetching of secrets, and automated token renewal.

### Secret Fetching

`daytona ` gives you the ability to pre-fetch secrets upon launch and store them in a specified JSON file after retrievial. The desrired secrets are specified by providing environment variables prefixed with `VAULT_SECRET_` and their value set as the vault path on which the secret can be accessed.

The following options `VAULT_SECRET_DATABASE_PASSWORD=secret/infrastructure/applicationZ/database SECRET_PATH=/tmp/sshhhhhhh` would yield the following at `/tmp/sshhhhhhh`:

```
{
      "secret/infrastructure/applicationZ/database": {
            "password": "YellowLamborghini"
      }
}
```

### Authentication

**Kubernetes** - Intended for use as an `initContainer` or sidecar container for managing secrets withing a pod.

`VAULT_SECRET_TEST=secret/infrastructure/applicationZ/secrets daytona -k8s-auth -token-path /home/vault/.vault-token -auth-role vault-role-name -secret-path /home/vault/secrets`


```yaml
---
apiVersion: v1
kind: Pod
metadata:
  name: awe-some-app
spec:
  volumes:
  - name: vault-data
    emptyDir:
      medium: Memory

  initContainers:
  - name: daytona
    image: daytona:latest
    volumeMounts:
    - name: vault-data
      mountPath: /home/vault
    env:
    - name: K8S_AUTH
      value: true
    - name: TOKEN_PATH
      value: /home/vault/.vault-token
    - name: AUTH_ROLE
      value: vault-role-name
    - name: SECRET_PATH
      value: /home/vault/secrets
    - name: VAULT_SECRET_TEST
      value: secret/infrastructure/applicationZ/secrets
````

Both execution examples above (assuming a successful authentication) would yield a vault token at `/home/vault/.vault-token` and any specified secrects written to `/home/vault/secrets` as

```
{
      "secret/infrastructure/applicationZ/secrets": {
            "secretA": "soosecret",
            "api_key": "helloooo"
      }
}
```

**EC2 IAM** - Intended for use on an AWS EC2 instance for managing secrets withing the instance.

`VAULT_SECRET_TEST=secret/infrastructure/applicationZ/secrets daytona -iam-auth -token-path /home/vault/.vault-token -auth-role vault-role-name -secret-path /home/vault/secrets`

The execution example above (assuming a successful authentication) would yield a vault token at `/home/vault/.vault-token` and any specified secrects written to `/home/vault/secrets` as

```
{
      "secret/infrastructure/applicationZ/secrets": {
            "secretA": "soosecret",
            "api_key": "helloooo"
      }
}
```

#### Usage Examples

```
Usage of ./daytona:
  -address string
        (env: VAULT_ADDR) (default "https://vault.secure.car:8200")
  -auth-role string
        the name of the role used for auth. used with either auth method (env: AUTH_ROLE)
  -auto-renew
        if enabled, starts the token renewal service (env: AUTO_RENEW)
  -iam-auth
        select AWS IAM vault auth as the vault authentication mechanism (env: IAM_AUTH)
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
        the threshold remaining in the vault token, in seconds, after which it should be renewed (env: RENEWAL_THRESHOLD) (default 43200)
  -secret-path string
        the full file path to store the JSON blob of the fetched secrets (env: SECRET_PATH)
  -token-path string
        a full file path where a token will be read from/written to (env: TOKEN_PATH) (default "~/.vault-token"
```
