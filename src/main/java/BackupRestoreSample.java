import com.microsoft.azure.keyvault.models.*;
import com.microsoft.azure.keyvault.webkey.JsonWebKeyType;
import com.microsoft.azure.management.keyvault.Vault;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class BackupRestoreSample extends KeyVaultSampleBase {

    public BackupRestoreSample() throws IOException {
        super();
    }

    /**
     * Backs up a secret and restores it to another key vault.
     *
     * @throws InterruptedException
     */
    public static void backupRestoreSecret() throws InterruptedException {

        //Create a key vault
        Vault firstVault = createKeyVault(getRandomName("vault"), RESOURCE_GROUP);

        //Add a secret to the vault
        String secretName = getRandomName("secret");
        String secretValue = "This secret is being moved from one vault to another";

        SecretBundle secret = keyVaultClient.setSecret(firstVault.vaultUri(), secretName, secretValue);
        System.out.printf("Created secret %s%n", secret.id());

        //List the secrets in the vaults
        List<SecretItem> secrets = keyVaultClient.getSecrets(firstVault.vaultUri());
        System.out.printf("Vault %s secrets: %s%n", firstVault.vaultUri(), Arrays.toString(secrets.toArray()));

        //Back up the secret
        BackupSecretResult backup = keyVaultClient.backupSecret(firstVault.vaultUri(), secretName);
        System.out.printf("Backed up secret %s%n", backup.toString());

        //Create a second vault
        Vault secondVault = createKeyVault(getRandomName("vault"), RESOURCE_GROUP);

        SecretBundle restored = keyVaultClient.restoreSecret(secondVault.vaultUri(), backup.value());
        System.out.printf("Restored secret %s%n", restored.toString());

        List<SecretItem> newVaultSecrets = keyVaultClient.getSecrets(secondVault.vaultUri());
        System.out.printf("Vault %s secrets: %s%n", secondVault.vaultUri(), Arrays.toString(newVaultSecrets.toArray()));

    }

    /**
     * Backs up a key vault key and restores it to another key vault.
     */
    public static void backupRestoreKey() throws InterruptedException {
        //Create a key vault
        Vault firstVault = createKeyVault(getRandomName("vault"), RESOURCE_GROUP);

        //Add a secret to the vault
        String keyName = getRandomName("key");

        KeyBundle key = keyVaultClient.createKey(firstVault.vaultUri(), keyName, JsonWebKeyType.RSA);
        System.out.printf("Created key %s%n", key.toString());

        //List the secrets in the vault
        List<KeyItem> keys = keyVaultClient.getKeys(firstVault.vaultUri());
        System.out.printf("Vault %s keys: %s%n", firstVault.vaultUri(), Arrays.toString(keys.toArray()));

        //Back up the secret
        BackupKeyResult backup = keyVaultClient.backupKey(firstVault.vaultUri(), keyName);
        System.out.printf("Backed up key %s%n", backup.toString());

        //Create a second vault
        Vault secondVault = createKeyVault(getRandomName("vault"), RESOURCE_GROUP);

        KeyBundle restored = keyVaultClient.restoreKey(secondVault.vaultUri(), backup.value());
        System.out.printf("Restored key %s%n", restored.toString());

        List<KeyItem> newVaultKeys = keyVaultClient.getKeys(secondVault.vaultUri());
        System.out.printf("Vault %s keys: %s%n", secondVault.vaultUri(), Arrays.toString(newVaultKeys.toArray()));
    }


}
