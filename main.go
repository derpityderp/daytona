package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/fatih/color"
	"github.com/hashicorp/vault/api"
	homedir "github.com/mitchellh/go-homedir"
)

type configuration struct {
	vaultAddress      string
	tokenPath         string
	k8sTokenPath      string
	k8sAuthMount      string
	iamAuthMount      string
	k8sAuth           bool
	iamAuth           bool
	authRoleName      string
	renewalThreshold  int64
	renewalInterval   int64
	secretPayloadPath string
}

var config configuration

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
	flag.StringVar(&config.tokenPath, "token-path", buildDefaultConfigItem("TOKEN_PATH", "~/.vault-token"), "file path where a token will be read from/written to (env: TOKEN_PATH)")
	flag.BoolVar(&config.k8sAuth, "k8s-auth", func() bool {
		b, err := strconv.ParseBool(buildDefaultConfigItem("K8S_AUTH", "false"))
		return err == nil && b
	}(), "select kubernetes vault auth as the vault authentication mechanism (env: K8S_AUTH)")
	flag.BoolVar(&config.iamAuth, "iam-auth", func() bool {
		b, err := strconv.ParseBool(buildDefaultConfigItem("IAM_AUTH", "false (env: IAM_AUTH"))
		return err == nil && b
	}(), "select AWS IAM vault auth as the vault authentication mechanism")
	flag.StringVar(&config.k8sTokenPath, "k8s-token-path", buildDefaultConfigItem("K8S_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token"), "kubernetes service account jtw token path (env: K8S_TOKEN_PATH)")
	flag.StringVar(&config.authRoleName, "auth-role", buildDefaultConfigItem("ROLE_NAME", ""), "used with either auth method (env: ROLE_NAME)")
	flag.StringVar(&config.k8sAuthMount, "k8s-auth-mount", buildDefaultConfigItem("K8S_AUTH_MOUNT", "kubernetes"), "the vault mount where k8s auth takes place (env: K8S_AUTH_MOUNT)")
	flag.StringVar(&config.iamAuthMount, "iam-auth-mount", buildDefaultConfigItem("IAM_AUTH_MOUNT", "aws"), "the vault mount where iam auth takes place (env: IAM_AUTH_MOUNT)")

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
	}(), "the threshold remaining in the vault token, in seconds, after which it should be renewed")
	flag.StringVar(&config.secretPayloadPath, "secret-path", buildDefaultConfigItem("SECRET_PATH", ""), "(env: SECRET_PATH)")
}

func main() {
	// env var overrides
	if addr := os.Getenv("VAULT_ADDR"); addr != "" {
		config.vaultAddress = addr
	}

	flag.Parse()

	if !config.k8sAuth && !config.iamAuth {
		log.Fatalln("You must provide an auth method: -k8s-auth or -iam-auth")
	}
	if config.k8sAuth && config.iamAuth {
		log.Fatalln("You cannot choose more than one auth method: -k8s-auth or -iam-auth")
	}

	if config.authRoleName == "" {
		log.Fatalln("you must supply a role name")
	}

	fullTokenPath, err := homedir.Expand(config.tokenPath)
	if err != nil {
		log.Println("could not expand", config.tokenPath, "using it as-is")
	} else {
		config.tokenPath = fullTokenPath
	}

	client, err := api.NewClient(&api.Config{Address: config.vaultAddress})
	if err != nil {
		color.Red("Could not configure vault client. error: %s", err)
		return
	}

	var authenticated bool
	var vaultToken string
	authTicker := time.Tick(time.Second * 1)
	for {
		if authenticated {
			log.Println("found a valid auth token, continuing")
			break
		}
		log.Println("checking for an existing, valid vault token")
		if client.Token() == "" {
			log.Println("no token found in VAULT_TOKEN, checking path", config.tokenPath)
			fileToken, err := ioutil.ReadFile(config.tokenPath)
			if err != nil {
				log.Println("can't read an existing token at", config.tokenPath, "starting authentication")
				authenticate(client, &config)
				continue
			}
			vaultToken = string(fileToken)
			client.SetToken(string(vaultToken))
		}

		_, err := client.Auth().Token().LookupSelf()
		if err != nil {
			log.Println("invalid token, what to do next?")
			authenticate(client, &config)
			continue
		} else {
			authenticated = true
		}

		<-authTicker
	}

	// if you send USR1, we'll re-fetch seekrits
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGUSR1)

	go func() {
		for {
			s := <-sigChan
			switch s {
			case syscall.SIGUSR1:
				secretFetcher(client, &config)
			}
		}
	}()
	secretFetcher(client, &config)
	renewService(client, &config, (time.Second * time.Duration(config.renewalInterval)))
}

func kubernetesAuth(client *api.Client, c *configuration) (string, error) {
	if c.k8sTokenPath == "" {
		return "", fmt.Errorf("kubernetes auth token path is mssing")
	}

	data, err := ioutil.ReadFile(c.k8sTokenPath)
	if err != nil {
		return "", fmt.Errorf("could not read JWT from file %s", err.Error())
	}
	jwt := string(bytes.TrimSpace(data))
	payload := map[string]interface{}{
		"role": c.authRoleName,
		"jwt":  jwt,
	}
	path := fmt.Sprintf("auth/%s/login", config.k8sAuthMount)
	log.Println("sending authentication request to", path)
	secret, err := client.Logical().Write(path, payload)
	if err != nil {
		return "", err
	}
	return secret.Auth.ClientToken, nil
}

func iamAuth(client *api.Client, c *configuration) (string, error) {
	loginData := make(map[string]interface{})
	stsSession, err := session.NewSession(&aws.Config{
		MaxRetries: aws.Int(5),
	})
	if err != nil {
		return "", err
	}
	svc := sts.New(stsSession)
	var params *sts.GetCallerIdentityInput
	stsRequest, _ := svc.GetCallerIdentityRequest(params)
	stsRequest.Sign()

	headersJSON, err := json.Marshal(stsRequest.HTTPRequest.Header)
	if err != nil {
		return "", err
	}
	requestBody, err := ioutil.ReadAll(stsRequest.HTTPRequest.Body)
	if err != nil {
		return "", err
	}
	loginData["iam_http_request_method"] = stsRequest.HTTPRequest.Method
	loginData["iam_request_url"] = base64.StdEncoding.EncodeToString([]byte(stsRequest.HTTPRequest.URL.String()))
	loginData["iam_request_headers"] = base64.StdEncoding.EncodeToString(headersJSON)
	loginData["iam_request_body"] = base64.StdEncoding.EncodeToString(requestBody)
	loginData["role"] = c.authRoleName

	secret, err := client.Logical().Write(fmt.Sprintf("auth/%s/login", c.iamAuthMount), loginData)
	if err != nil {
		return "", fmt.Errorf("could not login %s", err.Error())
	}
	return secret.Auth.ClientToken, nil
}

func authenticate(client *api.Client, c *configuration) bool {
	var vaultToken string
	var err error

	switch {
	case c.k8sAuth:
		vaultToken, err = kubernetesAuth(client, c)
		if err != nil {
			log.Println("error,", err.Error())
			return false
		}
	case c.iamAuth:
		vaultToken, err = iamAuth(client, c)
		if err != nil {
			log.Println("error,", err.Error())
			return false
		}
	default:
		panic("should never get here")
	}
	if vaultToken == "" {
		log.Fatalln("something weird happened, should have had the token, but do not")
	}

	err = ioutil.WriteFile(config.tokenPath, []byte(vaultToken), 0600)
	if err != nil {
		log.Println("could not write token to file", config.tokenPath)
		return false
	}
	client.SetToken(string(vaultToken))
	return true
}

func renewService(client *api.Client, c *configuration, interval time.Duration) {
	log.Println("starting the token renewer service on interval", interval)
	ticker := time.Tick(interval)
	for {
		result, err := client.Auth().Token().LookupSelf()
		if err != nil {
			log.Fatalln("the existing token failed renewal, exiting..")
		}
		ttl, err := result.TokenTTL()
		if ttl.Seconds() < float64(c.renewalThreshold) {
			fmt.Println("renewing: token ttl of", ttl.Seconds(), "is below threshold of ", c.renewalThreshold)
			secret, err := client.Auth().Token().RenewSelf(46800)
			if err != nil {
				log.Println("failed to renew the existing token:", err)
			}
			client.SetToken(string(secret.Auth.ClientToken))
		} else {
			log.Println(fmt.Sprintf("existing token ttl of %d seconds is still above the threshold (%d), skipping renewal", int64(ttl.Seconds()), c.renewalThreshold))
		}
		<-ticker
	}
}

func secretFetcher(client *api.Client, c *configuration) {
	log.Println("starting secret fetch")
	if c.secretPayloadPath == "" {
		log.Println("no secret payload path was provided, will not write secrets to disk")
		return
	}
	payloads := make(map[string]interface{})
	envs := os.Environ()
	for _, v := range envs {
		pair := strings.Split(v, "=")
		if strings.HasPrefix(pair[0], "VAULT_SECRET_") {
			x := os.Getenv(pair[0])
			if x == "" {
				continue
			}
			secret, err := client.Logical().Read(x)
			if err != nil {
				log.Println(fmt.Sprintf("failed retrieving secret %s: %s", x, err.Error()))
				continue
			}
			payloads[x] = secret.Data
		}
	}

	if len(payloads) == 0 {
		log.Println("could not find any environment variables prefixed with VAULT_SECRET_")
		return
	}
	// write the file
	payloadJSON, err := json.Marshal(payloads)
	if err != nil {
		log.Println("failed to convert secrets payload to json", err.Error())
		return
	}
	err = ioutil.WriteFile(config.secretPayloadPath, payloadJSON, 0600)
	if err != nil {
		log.Println("could not write secrets to file", config.secretPayloadPath, err)
		return
	}
	log.Println(fmt.Sprintf("wrote %d secrets to %s", len(payloads), config.secretPayloadPath))
}
