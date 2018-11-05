package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/hashicorp/vault/api"
	homedir "github.com/mitchellh/go-homedir"
)

var config struct {
	vaultAddress      string
	tokenPath         string
	k8sTokenPath      string
	k8sAuth           bool
	k8sAuthMount      string
	iamAuth           bool
	iamAuthMount      string
	gcpIAMAuth        bool
	gcpAuthMount      string
	gcpServiceAccount string
	vaultAuthRoleName string
	renewalThreshold  int64
	renewalInterval   int64
	secretPayloadPath string
	secretEnv         bool
	autoRenew         bool
	entrypoint        bool
	infinteAuth       bool
}

const defaultKeyName = "value"
const version = "0.0.2"

// buildDefaultConfigItem uses the following operation: ENV --> arg
func buildDefaultConfigItem(envKey string, def string) (val string) {
	val = os.Getenv(envKey)
	if val == "" {
		val = def
	}
	return
}

func init() {
	flag.StringVar(&config.vaultAddress, "address", buildDefaultConfigItem("VAULT_ADDR", "https://vault.secure.car:8200"), "(env: VAULT_ADDR)")
	flag.StringVar(&config.tokenPath, "token-path", buildDefaultConfigItem("TOKEN_PATH", "~/.vault-token"), "a full file path where a token will be read from/written to (env: TOKEN_PATH)")
	flag.BoolVar(&config.k8sAuth, "k8s-auth", func() bool {
		b, err := strconv.ParseBool(buildDefaultConfigItem("K8S_AUTH", "false"))
		return err == nil && b
	}(), "select kubernetes vault auth as the vault authentication mechanism (env: K8S_AUTH)")
	flag.BoolVar(&config.iamAuth, "iam-auth", func() bool {
		b, err := strconv.ParseBool(buildDefaultConfigItem("IAM_AUTH", "false"))
		return err == nil && b
	}(), "select AWS IAM vault auth as the vault authentication mechanism (env: IAM_AUTH)")
	flag.StringVar(&config.k8sTokenPath, "k8s-token-path", buildDefaultConfigItem("K8S_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token"), "kubernetes service account jtw token path (env: K8S_TOKEN_PATH)")
	flag.StringVar(&config.vaultAuthRoleName, "vault-auth-role", buildDefaultConfigItem("VAULT_AUTH_ROLE", ""), "the name of the role used for auth. used with either auth method (env: VAULT_AUTH_ROLE)")
	flag.StringVar(&config.k8sAuthMount, "k8s-auth-mount", buildDefaultConfigItem("K8S_AUTH_MOUNT", "kubernetes"), "the vault mount where k8s auth takes place (env: K8S_AUTH_MOUNT)")
	flag.StringVar(&config.iamAuthMount, "iam-auth-mount", buildDefaultConfigItem("IAM_AUTH_MOUNT", "aws"), "the vault mount where iam auth takes place (env: IAM_AUTH_MOUNT)")
	flag.BoolVar(&config.gcpIAMAuth, "gcp-auth", func() bool {
		b, err := strconv.ParseBool(buildDefaultConfigItem("GCP_AUTH", "false"))
		return err == nil && b
	}(), "select Google Cloud Platform IAM auth as the vault authentication mechanism (env: GCP_AUTH)")
	flag.StringVar(&config.gcpAuthMount, "gcp-auth-mount", buildDefaultConfigItem("GCP_AUTH_MOUNT", "gcp"), "the vault mount where gcp auth takes place (env: GCP_AUTH_MOUNT)")
	flag.StringVar(&config.gcpServiceAccount, "gcp-svc-acct", buildDefaultConfigItem("GCP_SVC_ACCT", ""), "the name of the service account authenticating (env: GCP_SVC_ACCT)")
	flag.Int64Var(&config.renewalInterval, "renewal-interval", func() int64 {
		b, err := strconv.ParseInt(buildDefaultConfigItem("RENEWAL_INTERVAL", "300"), 10, 64)
		if err != nil {
			return 900
		}
		return b
	}(), "how often to check the token's ttl and potentially renew it (env: RENEWAL_INTERVAL)")
	flag.Int64Var(&config.renewalThreshold, "renewal-threshold", func() int64 {
		b, err := strconv.ParseInt(buildDefaultConfigItem("RENEWAL_THRESHOLD", "43200"), 10, 64)
		if err != nil {
			return 43200
		}
		return b
	}(), "the threshold remaining in the vault token, in seconds, after which it should be renewed (env: RENEWAL_THRESHOLD)")
	flag.StringVar(&config.secretPayloadPath, "secret-path", buildDefaultConfigItem("SECRET_PATH", ""), "the full file path to store the JSON blob of the fetched secrets (env: SECRET_PATH)")
	flag.BoolVar(&config.autoRenew, "auto-renew", func() bool {
		b, err := strconv.ParseBool(buildDefaultConfigItem("AUTO_RENEW", "false"))
		return err == nil && b
	}(), "if enabled, starts the token renewal service (env: AUTO_RENEW)")
	flag.BoolVar(&config.entrypoint, "entrypoint", func() bool {
		b, err := strconv.ParseBool(buildDefaultConfigItem("ENTRYPOINT", "false"))
		return err == nil && b
	}(), "if enabled, execs the command after the separator (--) when done. mostly useful with -secret-env (env: ENTRYPOINT)")
	flag.BoolVar(&config.secretEnv, "secret-env", func() bool {
		b, err := strconv.ParseBool(buildDefaultConfigItem("SECRET_ENV", "false"))
		return err == nil && b
	}(), "write secrets to environment variables (env: SECRET_ENV)")
	flag.BoolVar(&config.infinteAuth, "infinite-auth", func() bool {
		b, err := strconv.ParseBool(buildDefaultConfigItem("INFINITE_AUTH", "false"))
		return err == nil && b
	}(), "infinitely attempt to authenticate (env: INFINITE_AUTH)")
}

func main() {
	// env var overrides
	if addr := os.Getenv("VAULT_ADDR"); addr != "" {
		config.vaultAddress = addr
	}

	log.SetPrefix("DAYTONA - ")
	flag.Parse()

	if !config.k8sAuth && !config.iamAuth && !config.gcpIAMAuth {
		log.Fatalln("You must provide an auth method: -k8s-auth or -iam-auth or -gcp-auth")
	}
	p := 0
	for _, v := range []bool{config.k8sAuth, config.iamAuth, config.gcpIAMAuth} {
		if v {
			p++
		}
	}
	if p > 1 {
		log.Fatalln("You cannot choose more than one auth method")
	}
	if config.vaultAuthRoleName == "" {
		log.Fatalln("you must supply a role name via VAULT_AUTH_ROLE or -vault-auth-role")
	}

	fullTokenPath, err := homedir.Expand(config.tokenPath)
	if err != nil {
		log.Println("could not expand", config.tokenPath, "using it as-is")
	} else {
		config.tokenPath = fullTokenPath
	}
	if f, err := os.Stat(config.tokenPath); err == nil {
		if f.IsDir() {
			log.Println("the token path you provided is a directory, automatically appending .vault-token filename")
			config.tokenPath = filepath.Join(config.tokenPath, ".vault-token")
		}
	}

	if config.secretPayloadPath != "" {
		if f, err := os.Stat(config.secretPayloadPath); err == nil {
			if f.IsDir() {
				log.Fatalln("the secret path you provided is a directory, please supply a full file path")
			}
		}
	}

	log.Println(fmt.Sprintf("DAYTONA - %s", version))
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = config.vaultAddress
	client, err := api.NewClient(vaultConfig)
	if err != nil {
		log.Fatalf("Could not configure vault client. error: %s", err)
	}

	var authenticated bool
	var vaultToken string

	bo := backoff.NewExponentialBackOff()
	bo.MaxInterval = time.Second * 15
	if config.infinteAuth {
		bo.MaxElapsedTime = 0
	} else {
		bo.MaxElapsedTime = time.Minute * 5
	}
	authTicker := backoff.NewTicker(bo)
	for _ = range authTicker.C {
		if authenticated {
			log.Println("found a valid vault token, continuing")
			break
		}
		log.Println("checking for an existing, valid vault token")
		if client.Token() == "" {
			log.Println("no token found in VAULT_TOKEN, checking path", config.tokenPath)
			fileToken, err := ioutil.ReadFile(config.tokenPath)
			if err != nil {
				log.Println("can't read an existing token at", config.tokenPath, "starting authentication")
				authenticate(client)
				continue
			}
			log.Println("found an existing token at", config.tokenPath)
			vaultToken = string(fileToken)
			client.SetToken(string(vaultToken))
		}

		_, err := client.Auth().Token().LookupSelf()
		if err != nil {
			log.Println("invalid token", err)
			authenticate(client)
			continue
		} else {
			authenticated = true
		}
	}

	if !config.infinteAuth && !authenticated {
		log.Fatalln("infinite authentication attempts are not enabled and the maximum elapsed time has been reached for authentication attempts. exiting.")
	}

	secretFetcher(client)
	if config.autoRenew {
		// if you send USR1, we'll re-fetch secrets
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan,
			syscall.SIGUSR1)

		go func() {
			for {
				s := <-sigChan
				switch s {
				case syscall.SIGUSR1:
					secretFetcher(client)
				}
			}
		}()
		renewService(client, (time.Second * time.Duration(config.renewalInterval)))
	}

	if config.entrypoint {
		args := flag.Args()
		log.Println("Will exec: ", args)
		binary, err := exec.LookPath(args[0])
		if err != nil {
			log.Fatalf("Error finding '%s' to exec: %s\n", args[0], err)
		}
		err = syscall.Exec(binary, args, os.Environ())
		if err != nil {
			log.Fatalf("Error from exec: %s\n", err)
		}
	}
}

func renewService(client *api.Client, interval time.Duration) {
	log.Println("starting the token renewer service on interval", interval)
	ticker := time.Tick(interval)
	for {
		result, err := client.Auth().Token().LookupSelf()
		if err != nil {
			log.Fatalln("the existing token failed renewal, exiting..")
		}
		ttl, err := result.TokenTTL()
		if ttl.Seconds() < float64(config.renewalThreshold) {
			fmt.Println("renewing: token ttl of", ttl.Seconds(), "is below threshold of ", config.renewalThreshold)
			secret, err := client.Auth().Token().RenewSelf(46800)
			if err != nil {
				log.Println("failed to renew the existing token:", err)
			}
			client.SetToken(string(secret.Auth.ClientToken))
			err = ioutil.WriteFile(config.tokenPath, []byte(secret.Auth.ClientToken), 0600)
			if err != nil {
				log.Println("could not write token to file", config.tokenPath, err.Error())
			}
		} else {
			log.Println(fmt.Sprintf("existing token ttl of %d seconds is still above the threshold (%d), skipping renewal", int64(ttl.Seconds()), config.renewalThreshold))
		}
		<-ticker
	}
}
