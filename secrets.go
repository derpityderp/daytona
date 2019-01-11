package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"

	"github.com/hashicorp/vault/api"
)

func secretFetcher(client *api.Client) {
	locations := prefixSecretLocationDefined()
	if config.secretPayloadPath == "" && !config.secretEnv && locations == nil {
		log.Println("no secret output method was configured, will not attempt to retrieve secrets")
		return
	}

	log.Println("starting secret fetch")
	secrets := make(map[string]string)

	envs := os.Environ()
	for _, v := range envs {
		pair := strings.Split(v, "=")
		envKey := pair[0]
		secretPath := os.Getenv(envKey)
		if secretPath == "" {
			continue
		}

		// Single secret
		if strings.HasPrefix(envKey, "VAULT_SECRET_") {
			secret, err := client.Logical().Read(secretPath)
			if err != nil {
				log.Fatalf("there was a problem fetching %s: %s\n", secretPath, err)
			}
			if secret == nil {
				log.Fatalf("secret not found: %s\n", secretPath)
			}
			log.Println("Found secret: ", secretPath)

			splitPath := strings.Split(secretPath, "/")
			keyName := splitPath[len(splitPath)-1]

			err = addSecrets(secrets, keyName, secret.Data)
			if err != nil {
				log.Fatalln(err)
			}
		}
		// Path containing multiple secrets
		if strings.HasPrefix(envKey, "VAULT_SECRETS_") {
			list, err := client.Logical().List(secretPath)
			if err != nil {
				log.Fatalf("there was a problem listing %s: %s\n", secretPath, err)
			}
			if list == nil || len(list.Data) == 0 {
				log.Fatalf("no secrets found under: %s\n", secretPath)
			}
			log.Println("starting iteration on", secretPath)
			// list.Data is like: map[string]interface {}{"keys":[]interface {}{"DATADOG_API_KEY", "DATADOG_APPLICATION_KEY", "PG_PASS"}}
			keys, ok := list.Data["keys"].([]interface{})
			if !ok {
				log.Fatalf("Unexpected list.Data format: %#v\n", list.Data)
			}
			for _, k := range keys {
				key, ok := k.(string)
				if !ok {
					log.Fatalf("Non-string secret name: %#v\n", key)
				}
				constructedPath := path.Join(secretPath, key)
				secret, err := client.Logical().Read(constructedPath)
				if err != nil {
					log.Fatalf("failed retrieving secret %s: %s\n", constructedPath, err)
				}
				if secret == nil {
					log.Fatalf("vault listed a secret '%s', but got not-found trying to read it at '%s'; very strange\n", key, constructedPath)
				}
				err = addSecrets(secrets, key, secret.Data)
				if err != nil {
					log.Fatalln(err)
				}
			}
		}
	}

	if len(locations) == 0 && config.secretPayloadPath != "" {
		err := writeJSONSecrets(secrets, config.secretPayloadPath)
		if err != nil {
			log.Fatalln(err)
		}
	} else {
		err := writeSecretsToDestination(secrets, config.secretPayloadPath, locations)
		if err != nil {
			log.Fatalln(err)
		}
	}

	if config.secretEnv {
		err := setEnvSecrets(secrets)
		if err != nil {
			log.Fatalln(err)
		}
	}
}

func writeSecretsToDestination(secrets map[string]string, filepath string, locations map[string]string) error {
	for secret, secretValue := range secrets {
		if secretDestination, ok := locations[secret]; ok {
			err := ioutil.WriteFile(secretDestination, []byte(secretValue), 0600)
			if err != nil {
				return fmt.Errorf("could not write secrets to file '%s': %s", secretDestination, err)
			}
			log.Printf("wrote secret to %s\n", secretDestination)
		}
	}

	// If there is no filepath configured or all hte secrets have been
	// consumed by expandedSecrets, return.
	if filepath == "" || len(secrets) == 0 {
		return nil
	}

	payloadJSON, err := json.Marshal(secrets)
	if err != nil {
		return fmt.Errorf("failed to convert secrets payload to json: %s", err)
	}
	err = ioutil.WriteFile(filepath, payloadJSON, 0600)
	if err != nil {
		return fmt.Errorf("could not write secrets to file '%s': %s", filepath, err)
	}
	log.Printf("wrote %d secrets to %s\n", len(secrets), filepath)
	return nil
}

func writeJSONSecrets(secrets map[string]string, filepath string) error {
	payloadJSON, err := json.Marshal(secrets)
	if err != nil {
		return fmt.Errorf("failed to convert secrets payload to json: %s", err)
	}
	err = ioutil.WriteFile(filepath, payloadJSON, 0600)
	if err != nil {
		return fmt.Errorf("could not write secrets to file '%s': %s", filepath, err)
	}
	log.Printf("wrote %d secrets to %s\n", len(secrets), filepath)
	return nil
}

func setEnvSecrets(secrets map[string]string) error {
	for k, v := range secrets {
		err := os.Setenv(k, v)
		if err != nil {
			return fmt.Errorf("Error from os.Setenv: %s", err)
		}
		log.Println("Set env var", k)
	}
	return nil
}

func addSecret(secrets map[string]string, k string, v interface{}) error {
	if secrets[k] != "" {
		return errors.New("Duplicate secret name: " + k)
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("Secret '%s' has non-string value: %#v", k, v)
	}
	secrets[k] = s
	return nil
}

func addSecrets(secrets map[string]string, keyName string, secretData map[string]interface{}) error {
	// Return last error encountered during processing, if any
	var lastErr error

	// detect and fetch defaultKeyName
	if secretData[defaultKeyName] != nil {
		err := addSecret(secrets, keyName, secretData[defaultKeyName])
		if err != nil {
			lastErr = err
		}
		delete(secretData, defaultKeyName)
	}

	// iterate over remaining map entries
	for k, v := range secretData {
		expandedKeyName := fmt.Sprintf("%s_%s", keyName, k)
		err := addSecret(secrets, expandedKeyName, v)
		if err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// prefixSecretLocationDefined checks whether any of the configured
// secrets for fetching are using an explicit destination.
func prefixSecretLocationDefined() map[string]string {
	var locations map[string]string
	envs := os.Environ()
	for _, v := range envs {
		pair := strings.Split(v, "=")
		envKey := pair[0]
		if strings.HasPrefix(envKey, secretLocationPrefix) {
			if locations == nil {
				locations = map[string]string{}
			}
			secret := strings.TrimPrefix(envKey, secretLocationPrefix)
			locations[secret] = os.Getenv(envKey)
		}
	}
	return locations
}
