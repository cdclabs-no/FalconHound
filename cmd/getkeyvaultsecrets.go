package cmd

import (
	"context"
	"fmt"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/spf13/viper"
)

func GetSecretFromAzureKeyVault(keyVaultName string, secretName string) (string, error) {
	// Declare a credential variable
	var cred azidentity.TokenCredential
	var err error

	// Check if keyvault.appID or keyvault.appSecret is empty
	appID := viper.GetString("keyvault.appID")
	appSecret := viper.GetString("keyvault.appSecret")
	tenantID := viper.GetString("keyvault.tenantID")

	if appID == "" || appSecret == "" {
		// Use DefaultAzureCredential if appID or appSecret is empty
		log.Println("Using DefaultAzureCredential to authenticate to the KeyVault.")
		cred, err = azidentity.NewDefaultAzureCredential(nil)
	} else {
		// Use ClientSecretCredential if appID and appSecret are provided
		log.Println("Using ClientSecretCredential to authenticate to the KeyVault.")
		cred, err = azidentity.NewClientSecretCredential(tenantID, appID, appSecret, nil)
	}

	if err != nil {
		log.Fatalf("Failed to create the credentials: %v", err)
	}

	// Create a new client using the credentials
	client, err := azsecrets.NewClient(keyVaultName, cred, nil)
	if err != nil {
		log.Fatalf("Failed to create the client: %v", err)
	}

	// Get the secret
	secretResponse, err := client.GetSecret(context.Background(), secretName, "", &azsecrets.GetSecretOptions{})
	if err != nil {
		return "", fmt.Errorf("Failed to get the secret: %v", err)
	}

	return *secretResponse.Value, nil
}

