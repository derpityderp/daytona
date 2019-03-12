package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"

	"cloud.google.com/go/compute/metadata"
	"github.com/briankassouf/jose/jws"
)

// InferK8SConfig attempts to replace default configuration parameters on K8S with ones infered from the k8s environment
func InferK8SConfig() {
	if config.vaultAuthRoleName == "" {
		saName, err := InferVaultAuthRoleName()
		if err != nil {
			log.Printf("Unable to infer SA Name: %v\n", err)
		} else {
			config.vaultAuthRoleName = saName
		}
	}

	// Check for default value
	if config.k8sAuthMount == "kubernetes" {
		vaultAuthMount, err := InferVaultAuthMount()
		if err != nil {
			log.Printf("Unable to infer K8S Vault Auth Mount: %v\n", err)
		} else {
			config.k8sAuthMount = vaultAuthMount
		}
	}
}

// InferVaultAuthRoleName figures out the current k8s service account name, and returns it.
// This can be assumed to match a a vault role if configured properly.
func InferVaultAuthRoleName() (string, error) {
	data, err := ioutil.ReadFile(config.k8sTokenPath)
	if err != nil {
		return "", fmt.Errorf("could not read JWT from file %s", err.Error())
	}

	jwt := bytes.TrimSpace(data)

	// Parse into JWT
	parsedJWT, err := jws.ParseJWT(jwt)
	if err != nil {
		return "", err
	}

	saName, ok := parsedJWT.Claims().Get("kubernetes.io/serviceaccount/service-account.name").(string)
	if !ok || saName == "" {
		return "", errors.New("could not parse UID from claims")
	}

	return saName, nil
}

// InferVaultAuthMount attempts to figure out where the auth path for the current k8s cluster is in vault, and return it
func InferVaultAuthMount() (string, error) {
	clusterName, err := metadata.InstanceAttributeValue("cluster-name")

	return fmt.Sprintf("kubernetes-gcp-%s", clusterName), err
}
