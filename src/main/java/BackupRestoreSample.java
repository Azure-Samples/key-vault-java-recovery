import com.azure.core.http.rest.PagedIterable;
import com.azure.resourcemanager.keyvault.models.Vault;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.models.CreateRsaKeyOptions;
import com.azure.security.keyvault.keys.models.KeyOperation;
import com.azure.security.keyvault.keys.models.KeyProperties;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.azure.security.keyvault.secrets.models.SecretProperties;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

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

        SecretClient secretClient = new SecretClientBuilder()
                .vaultUrl(firstVault.vaultUri())
                .credential(createToken())
                .buildClient();

        KeyVaultSecret secret = secretClient.setSecret(secretName, secretValue);
        System.out.printf("Created secret with name: %s%n", secret.getName());

        //List the secrets in the vaults
        PagedIterable<SecretProperties> secretProperties = secretClient.listPropertiesOfSecrets();
        System.out.printf("Vault %s secrets: %s%n", firstVault.vaultUri(),
                Arrays.toString(secretProperties.stream().map(SecretProperties::getName).toArray()));

        //Back up the secret
        byte[] backup = secretClient.backupSecret(secretName);
        System.out.printf("Backed up secret: %s%n", new String(backup, StandardCharsets.UTF_8));

        //Create a second vault
        Vault secondVault = createKeyVault(getRandomName("vault"), RESOURCE_GROUP);
        SecretClient secondSecretClient = new SecretClientBuilder()
                .vaultUrl(secondVault.vaultUri())
                .credential(createToken())
                .buildClient();

        KeyVaultSecret restoredSecret = secondSecretClient.restoreSecretBackup(backup);
        System.out.printf("Restored secret with name: %s%n", restoredSecret.getName());

        PagedIterable<SecretProperties> newVaultSecretProperties = secondSecretClient.listPropertiesOfSecrets();
        System.out.printf("Vault %s secrets: %s%n", secondVault.vaultUri(),
                Arrays.toString(newVaultSecretProperties.stream().map(SecretProperties::getName).toArray()));

    }

    /**
     * Backs up a key vault key and restores it to another key vault.
     */
    public static void backupRestoreKey() throws InterruptedException {
        //Create a key vault
        Vault firstVault = createKeyVault(getRandomName("vault"), RESOURCE_GROUP);

        //Add a secret to the vault
        String keyName = getRandomName("key");

        KeyClient keyClient = new KeyClientBuilder()
                .vaultUrl(firstVault.vaultUri())
                .credential(createToken())
                .buildClient();
        KeyVaultKey key = keyClient.createRsaKey(new CreateRsaKeyOptions(keyName)
                .setKeyOperations(KeyOperation.UNWRAP_KEY, KeyOperation.WRAP_KEY, KeyOperation.DECRYPT,
                        KeyOperation.ENCRYPT, KeyOperation.SIGN, KeyOperation.VERIFY));
        System.out.printf("Created key with name: %s%n", key.getName());

        //List the secrets in the vault
        PagedIterable<KeyProperties> keyProperties = keyClient.listPropertiesOfKeys();
        System.out.printf("Vault %s keys: %s%n", firstVault.vaultUri(),
                Arrays.toString(keyProperties.stream().map(KeyProperties::getName).toArray()));

        //Back up the secret
        byte[] backup = keyClient.backupKey(keyName);
        System.out.printf("Backed up key: %s%n", new String(backup, StandardCharsets.UTF_8));

        //Create a second vault
        Vault secondVault = createKeyVault(getRandomName("vault"), RESOURCE_GROUP);
        KeyClient secondKeyClient = new KeyClientBuilder()
                .vaultUrl(secondVault.vaultUri())
                .credential(createToken())
                .buildClient();

        KeyVaultKey restoredKey = secondKeyClient.restoreKeyBackup(backup);
        System.out.printf("Restored key with name: %s%n", restoredKey.getName());

        PagedIterable<KeyProperties> newVaultKeyProperties = secondKeyClient.listPropertiesOfKeys();
        System.out.printf("Vault %s keys: %s%n", secondVault.vaultUri(),
                Arrays.toString(newVaultKeyProperties.stream().map(KeyProperties::getName).toArray()));
    }


}
