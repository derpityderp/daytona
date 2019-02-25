# DAYTONA

This is intended to be a lighter, alternate implementation of the vault client CLI, but for servers and containers. Its core features are the abilty to automate authentication, fetching of secrets, and automated token renewal.

Previously, authentication to and secret retrevial from vault via a server or container was a delicate balance of shell scripts or potentially lengthy http implementations, similar to:

```
vault login -token-only -method=aws role=$VAULT_ROLE"
THING="$(vault read -field=key secret/infrastrucure/appZ/thing)"
ANOTHER_THING="$(vault read -field=key secret/infrastrucure/appZ/another_thing)"
echo $THING | appZ
....
```

Instead, a single binary can be used to accomplish most of these goals.

### Authentication

The following authentication methods are supported:

 - **Kubernetes** - Uses the kubernetes service account jwt token for vault authentication. Intended for use as an `initContainer` or sidecar container for managing secrets withing a pod.

 - **AWS IAM** - Uses the IAM Role Credentials for vault authentication. Intended for use on an AWS resources that utilize IAM roles.

 - **GCP IAM** - Use GCP IAM Auth in combination with Service Accounts for vault authentication. Intended for use on an GCP resources that utilize IAM roles with service accounts.

----

## Secret Fetching

`daytona ` gives you the ability to pre-fetch secrets upon launch and store them in environment variables and/or a specified JSON file after retrievial. The desired secrets are specified by providing environment variables prefixed with `VAULT_SECRET_` and their value set as the vault path on which the secret can be accessed, or `VAULT_SECRETS_` with a path from which all secrets should be loaded. Any unique value can be appended to `VAULT_SECRET_` in order to provide the ability to supply multiple secret paths. e.g. `VAULT_SECRETS_APPLICATION=secret/application/my-team/sandbox/my-project`, `VAULT_SECRETS_COMMON=secret/infra/common`, `VAULT_SECRET_1=secret/application/my-team/shared/DATADOG_API_KEY`.

If a secret in Vault has a corresponding environment variable pointed at a file location prefixed with `DAYTONA_SECRET_DESTINATION` then the secret is written to that location instead of the default destination. For example, if `VAULT_SECRET_DATADOG_API_KEY=secret/application/my-team/shared/DATADOG_API_KEY` and `DAYTONA_SECRET_DESTINATION_DATADOG_API_KEY='/etc/datadog.conf'` are defined then the key is written to /etc/datadog.conf instead of the default location (configured via the secret-path flag or SECRET_PATH environment variable). Other keys are written at the normal location. For convenience, `DAYTONA_SECRET_DESTINATION_DATADOG_API_KEY` will work if the vault key is `DATADOG-API-KEY` or `DATADOG_API_KEY`. Periods are ignored in the vault key name.

#### Outputs

Fetched secrets can be output to file in JSON format via the `-secret-path` flag or to enviornment variables via `-secret-env`. `-secret-env` will have no effect unless used with the `-entrypoint` flag so that any popoulated environment variables are passed to a provided executable.

#### Data and Secret Key Layout

`daytona` prefers secret data containing the key `value`, but is able to detect other key names (this decreases readability, as you'll see later below) For example:

`secret/infrastructure/applicationZ/database` should have its secret data stored as:

```
{
  "value": "databasepassword"
}
```

If `-secret-env` is supplied at runtime, the above example would be written to an environment variable as: `DATABASE=databasepassword`, while `-secret-path /tmp/secrets` would be written to a file as:

```
{
  "database": "password"
}
```

If instead your data is stored in the **`non-preferred`** format at `secret/infrastructure/applicationZ/database` as 

```
{
  "db_username": "robot",
  "db_password": "databasepassword"
}
```

your secret data will be stored as combination of `SECRETKEYNAME_DATAKEYNAME=value`. e.g. `DATABASE_DB_USERNAME=robot` and `DATABASE_DB_password=databasepassword` and respetively as written to file as:

```
{
  "database_db_username": "robot",
  "database_db_password": "databasepassword"
}
```


### Supported Paths

**Top Level Path Iteration**

Consider the following path, `secret/infrastructure/applicationZ` which when listed, contains the following keys:

```
database
api_key
moredatahere/
```

`daytona` would iterate through all of these values attempting to read their secret data. Because `moredatahere/` is a key in a longer path, it would be skipped.


**Direct Path**

If provided a direct path `secret/infrastructure/applicationZ/database`, the application will process secret data as outlined in **Data and Secret Key Layout** above.

----

## Implementation Examples

You have configured a vault k8s auth role named `awesome-app-vault-role-name` that contains the following configuration:

```
{
  "bound_service_account_names": [
    "awe-some-app"
  ],
  "bound_service_account_namespaces": [
    "elite-squad"
  ],
  "policies": [
    "too-permissive"
  ],
  "ttl": 72000
}
```

**Pod Definition Example**:

Be sure to populate the `serviceAccountName` and `VAULT_AUTH_ROLE` with the corresponding values from your vault k8s auth role as described above.

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
  serviceAccountName: awe-some-app
  - name: daytona
    image: gcr.io/cruise-gcr-dev/daytona@sha256:6df2fb8fa114f00d25cac199ecdf5b0e44659af8de21451abf8d8e7cdeceaa3e
    volumeMounts:
    - name: vault-data
      mountPath: /home/vault
    env:
    - name: K8S_AUTH
      value: "true"
    - name : K8S_AUTH_MOUNT
      value: "kubernetes-gcp-paas-dev-us-west1"
    - name: SECRET_ENV
      value: "true"
    - name: TOKEN_PATH
      value: /home/vault/.vault-token
    - name: VAULT_AUTH_ROLE
      value: awesome-app-vault-role-name
    - name: SECRET_PATH
      value: /home/vault/secrets
    - name: VAULT_SECRETS_APP
      value: secret/infrastructure/applicationZ
    - name: VAULT_SECRETS_GLOBAL
      value: secret/infrastructure/global/metrics
````

The example above (assuming a successful authentication) would yield a vault token at `/home/vault/.vault-token` and any specified secrects written to `/home/vault/secrets` as

```
{
  "api_key": "soosecret",
  "database": "databasepassword",
  "metrics": "helloooo"
}
```
as a representation of the following vault data:

`secret/infrastructure/applicationZ/api_key`

```
{
  "value": "soosecret"
}
```

`secret/infrastructure/applicationZ/database`

```
{
  "value": "databasepassword"
}
```

`secret/infrastructure/global/metrics`

```
{
  "value": "helloooo"
}
```


**AWS IAM Example (Written to file)**:

`VAULT_SECRETS_TEST=secret/infrastructure/applicationZ/secrets daytona -iam-auth -token-path /home/vault/.vault-token -vault-auth-role vault-role-name -secret-path /home/vault/secrets`

The execution example above (assuming a successful authentication) would yield a vault token at `/home/vault/.vault-token` and any specified secrects written to `/home/vault/secrets` as

```
{
  "secrets_secretA": "soosecret",
  "secrets_api_key": "helloooo"
}
```

as a representation of the following vault data:

`secret/infrastructure/applicationZ/secrets`

```
{
  "secretA": "soosecret",
  "api_key": "helloooo"
}
```

**AWS IAM Example (As a container entrypoint)**:

In a `Dockerfile`:
```
ENTRYPOINT [ "./daytona", "-secret-env", "-iam-auth", "-vault-auth-role", "vault-role-name", "-entrypoint", "--" ]
```

combined with supplying the follwing during a `docker run `:

`-e "VAULT_SECRETS_APP=secret/infrastructure/applicationZ"`

would yield the following environment variables in a container:
```
API_KEY=soosecret
DATABASE=databasepassword
```

as a representation of the following vault data:

`secret/infrastructure/applicationZ/api_key`

```
{
  "value": "soosecret"
}
```

`secret/infrastructure/applicationZ/database`

```
{
  "value": "databasepassword"
}
```
----

#### Usage Examples

```
Usage of daytona:
  -address string
        (env: VAULT_ADDR) (default "https://vault.secure.car:8200")
  -auto-renew
        if enabled, starts the token renewal service (env: AUTO_RENEW)
  -entrypoint
        if enabled, execs the command after the separator (--) when done. mostly useful with -secret-env (env: ENTRYPOINT)
  -gcp-auth
        select Google Cloud Platform IAM auth as the vault authentication mechanism (env: GCP_AUTH)
  -gcp-auth-mount string
        the vault mount where gcp auth takes place (env: GCP_AUTH_MOUNT) (default "gcp")
  -gcp-svc-acct string
        the name of the service account authenticating (env: GCP_SVC_ACCT)
  -iam-auth
        select AWS IAM vault auth as the vault authentication mechanism (env: IAM_AUTH)
  -iam-auth-mount string
        the vault mount where iam auth takes place (env: IAM_AUTH_MOUNT) (default "aws")
  -infinite-auth
        infinitely attempt to authenticate (env: INFINITE_AUTH)
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
  -secret-env
        write secrets to environment variables (env: SECRET_ENV)
  -secret-path string
        the full file path to store the JSON blob of the fetched secrets (env: SECRET_PATH)
  -token-path string
        a full file path where a token will be read from/written to (env: TOKEN_PATH) (default "~/.vault-token")
  -vault-auth-role string
        the name of the role used for auth. used with either auth method (env: VAULT_AUTH_ROLE)
```
