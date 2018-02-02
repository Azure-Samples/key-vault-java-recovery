package com.microsoft.azure;

import java.io.IOException;
import java.util.List;

import com.microsoft.azure.keyvault.models.BackupKeyResult;
import com.microsoft.azure.keyvault.models.BackupSecretResult;
import com.microsoft.azure.keyvault.models.KeyBundle;
import com.microsoft.azure.keyvault.models.KeyItem;
import com.microsoft.azure.keyvault.models.SecretBundle;
import com.microsoft.azure.keyvault.models.SecretItem;
import com.microsoft.azure.keyvault.requests.CreateKeyRequest;
import com.microsoft.azure.keyvault.requests.SetSecretRequest;
import com.microsoft.azure.keyvault.webkey.JsonWebKeyType;
import com.microsoft.azure.management.keyvault.Vault;

public class BackupRestoreSample extends KeyVaultSampleBase{
	
	public BackupRestoreSample() throws IOException {
		super();
	}

	public static void backupRestoreSecret() throws InterruptedException {
		
		//Create a vault
		Vault vault1 = createKeyVault();
		String secretName = getRandomName("secret");
		String secretValue = "This is a secret value to be migrated from one vault to another";
		
		//Add secret to a vault.
		SecretBundle secret = keyVaultClient.setSecret(new SetSecretRequest.Builder(vault1.vaultUri(), secretName, secretValue).build());
		System.out.printf("Created secret %s%n", secret.id());

		//List the secrets in the vault
		List<SecretItem> secrets = keyVaultClient.listSecrets(vault1.vaultUri());
		System.out.printf("These are the secrets in the vault %s: %s.%n", vault1.vaultUri(), getListOfSecretIds(secrets));
		
		//Back up the secret
		BackupSecretResult backedUpSecret = keyVaultClient.backupSecret(vault1.vaultUri(), secretName);
		System.out.println("Backed up secret");
		
		//create a second vault
		Vault vault2 = createKeyVault();
	
		//Restore the secret to the new vault
		SecretBundle restoredSecret = keyVaultClient.restoreSecret(vault2.vaultUri(), backedUpSecret.value());
		System.out.printf("Restored secret %s%n", restoredSecret.id());
		
		//List the secrets in the new vault
		List<SecretItem> newSecrets = keyVaultClient.listSecrets(vault2.vaultUri());
		System.out.printf("These are the secrets in the vault %s: %s.%n", vault2.vaultUri(), getListOfSecretIds(newSecrets));
		
		SecretBundle newSecret = keyVaultClient.getSecret(restoredSecret.id());
		System.out.printf("The new secret's value is still: %s", newSecret.value());
	}
	
	public static void backupRestoreKey() throws InterruptedException {
		
		//Create a vault
		Vault vault1 = createKeyVault();
		
		//Create a key in the vault
		String keyName = getRandomName("key");
		KeyBundle key = keyVaultClient.createKey(new CreateKeyRequest.Builder(vault1.vaultUri(), keyName, JsonWebKeyType.RSA).build());
		System.out.printf("Created key %s%n", key.keyIdentifier());
		
		//List the keys in the vault
		List<KeyItem> keys = keyVaultClient.listKeys(vault1.vaultUri());
		System.out.printf("These are the keys in the vault %s%n", getListOfKeyIds(keys));
		
		//Back up the key
		BackupKeyResult backupKey = keyVaultClient.backupKey(vault1.vaultUri(), keyName);
		System.out.println("Backed up key");
		
		//Create a second vault.
		Vault vault2 = createKeyVault();
		
		//Restore the key to the new vault
		KeyBundle restoredKey = keyVaultClient.restoreKey(vault2.vaultUri(), backupKey.value());
		System.out.printf("Restored key %s%n", restoredKey.keyIdentifier());
		
		//List the keys in the vault
		List<KeyItem> newKeys = keyVaultClient.listKeys(vault2.vaultUri());
		System.out.printf("These are the keys in the vault %s%n", getListOfKeyIds(newKeys));

	}
}
