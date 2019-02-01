package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault/api"
	"golang.org/x/oauth2"
	"google.golang.org/api/iam/v1"
)

func authenticate(client *api.Client) bool {
	var vaultToken string
	var err error

	switch {
	case config.k8sAuth:
		vaultToken, err = kubernetesAuth(client)
		if err != nil {
			log.Println("error,", err.Error())
			return false
		}
	case config.iamAuth:
		vaultToken, err = iamAuth(client)
		if err != nil {
			log.Println("error,", err.Error())
			return false
		}
	case config.gcpIAMAuth:
		vaultToken, err = gcpAuth(client)
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
		log.Printf("could not write token to %s: %v\n", config.tokenPath, err)
		return false
	}
	client.SetToken(string(vaultToken))
	return true
}

func kubernetesAuth(client *api.Client) (string, error) {
	log.Println("attempting kubernetes auth..")
	if config.k8sTokenPath == "" {
		return "", fmt.Errorf("kubernetes auth token path is mssing")
	}

	data, err := ioutil.ReadFile(config.k8sTokenPath)
	if err != nil {
		return "", fmt.Errorf("could not read JWT from file %s", err.Error())
	}
	jwt := string(bytes.TrimSpace(data))
	payload := map[string]interface{}{
		"role": config.vaultAuthRoleName,
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

func iamAuth(client *api.Client) (string, error) {
	log.Println("attempting aws iam auth..")
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
	loginData["role"] = config.vaultAuthRoleName

	secret, err := client.Logical().Write(fmt.Sprintf("auth/%s/login", config.iamAuthMount), loginData)
	if err != nil {
		return "", fmt.Errorf("could not login %s", err.Error())
	}
	return secret.Auth.ClientToken, nil
}

func gcpAuth(client *api.Client) (string, error) {
	log.Println("attempting gcp iam auth..")
	if config.gcpServiceAccount == "" {
		return "", errors.New("-gcp-svc-acct is missing")
	}
	m := map[string]string{
		"role":            config.vaultAuthRoleName,
		"mount":           config.gcpAuthMount,
		"service_account": config.gcpServiceAccount,
	}

	loginToken, err := getGCPSignedJwt(config.vaultAuthRoleName, m)
	if err != nil {
		return "", err
	}

	path := fmt.Sprintf("auth/%s/login", config.gcpAuthMount)
	secret, err := client.Logical().Write(
		path,
		map[string]interface{}{
			"role": config.vaultAuthRoleName,
			"jwt":  loginToken,
		})

	if err != nil {
		return "", err
	}
	if secret == nil {
		return "nil", fmt.Errorf("empty response from credential provider")
	}

	return secret.Auth.ClientToken, nil
}

func getGCPSignedJwt(role string, m map[string]string) (string, error) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, cleanhttp.DefaultClient())

	credentials, tokenSource, err := gcputil.FindCredentials(m["credentials"], ctx, iam.CloudPlatformScope)
	if err != nil {
		return "", fmt.Errorf("could not obtain credentials: %v", err)
	}

	httpClient := oauth2.NewClient(ctx, tokenSource)

	serviceAccount, ok := m["service_account"]
	if !ok && credentials != nil {
		serviceAccount = credentials.ClientEmail
	}
	if serviceAccount == "" {
		return "", errors.New("could not obtain service account from credentials (are you using Application Default Credentials?). You must provide a service account to authenticate as")
	}

	project, ok := m["project"]
	if !ok {
		if credentials != nil {
			project = credentials.ProjectId
		} else {
			project = "-"
		}
	}

	var ttl = time.Duration(15) * time.Minute

	jwtPayload := map[string]interface{}{
		"aud": fmt.Sprintf("http://vault/%s", role),
		"sub": serviceAccount,
		"exp": time.Now().Add(ttl).Unix(),
	}
	payloadBytes, err := json.Marshal(jwtPayload)
	if err != nil {
		return "", fmt.Errorf("could not convert JWT payload to JSON string: %v", err)
	}

	jwtReq := &iam.SignJwtRequest{
		Payload: string(payloadBytes),
	}

	iamClient, err := iam.New(httpClient)
	if err != nil {
		return "", fmt.Errorf("could not create IAM client: %v", err)
	}

	resourceName := fmt.Sprintf("projects/%s/serviceAccounts/%s", project, serviceAccount)
	resp, err := iamClient.Projects.ServiceAccounts.SignJwt(resourceName, jwtReq).Do()
	if err != nil {
		return "", fmt.Errorf("unable to sign JWT for %s using given Vault credentials: %v", resourceName, err)
	}

	return resp.SignedJwt, nil
}
