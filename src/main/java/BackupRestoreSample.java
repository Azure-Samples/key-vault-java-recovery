import com.azure.core.http.rest.PagedIterable;
import com.azure.resourcemanager.keyvault.models.Key;
import com.azure.resourcemanager.keyvault.models.Secret;
import com.azure.resourcemanager.keyvault.models.Vault;
import com.azure.security.keyvault.keys.KeyAsyncClient;
import com.azure.security.keyvault.keys.models.CreateRsaKeyOptions;
import com.azure.security.keyvault.keys.models.KeyOperation;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import com.azure.security.keyvault.secrets.SecretAsyncClient;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

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

        SecretAsyncClient secretAsyncClient = firstVault.secretClient();

        KeyVaultSecret secret = secretAsyncClient.setSecret(secretName, secretValue).block();
        System.out.printf("Created secret %s%n", secret.getId());

        //List the secrets in the vaults
        List<Secret> secrets = firstVault.secrets().list().stream().collect(Collectors.toList());
        System.out.printf("Vault %s secrets: %s%n", firstVault.vaultUri(), Arrays.toString(secrets.toArray()));

        //Back up the secret
        byte[] backup = secretAsyncClient.backupSecret(secretName).block();
        System.out.printf("Backed up secret %s%n", new String(backup, StandardCharsets.UTF_8));

        //Create a second vault
        Vault secondVault = createKeyVault(getRandomName("vault"), RESOURCE_GROUP);

        KeyVaultSecret restored = secondVault.secretClient().restoreSecretBackup(backup).block();
        System.out.printf("Restored secret %s%n", restored.toString());

        List<Secret> newVaultSecrets = secondVault.secrets().list().stream().collect(Collectors.toList());
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

        KeyAsyncClient keyAsyncClient = firstVault.keyClient();
        KeyVaultKey key = keyAsyncClient.createRsaKey(new CreateRsaKeyOptions(keyName)
                .setKeyOperations(KeyOperation.UNWRAP_KEY, KeyOperation.WRAP_KEY, KeyOperation.DECRYPT,
                        KeyOperation.ENCRYPT, KeyOperation.SIGN, KeyOperation.VERIFY
                )).block();
        System.out.printf("Created key %s%n", key.toString());

        //List the secrets in the vault
        PagedIterable<Key> keys = firstVault.keys().list();
        System.out.printf("Vault %s keys: %s%n", firstVault.vaultUri(), Arrays.toString(keys.stream().collect(Collectors.toList()).toArray()));

        //Back up the secret
        byte[] backup = keyAsyncClient.backupKey(keyName).block();
        System.out.printf("Backed up key %s%n", new String(backup, StandardCharsets.UTF_8));

        //Create a second vault
        Vault secondVault = createKeyVault(getRandomName("vault"), RESOURCE_GROUP);

        KeyVaultKey restored = secondVault.keyClient().restoreKeyBackup(backup).block();
        System.out.printf("Restored key %s%n", restored.toString());

        PagedIterable<Key> newVaultKeys = secondVault.keys().list();
        System.out.printf("Vault %s keys: %s%n", secondVault.vaultUri(), Arrays.toString(newVaultKeys.stream().collect(Collectors.toList()).toArray()));
    }


}
