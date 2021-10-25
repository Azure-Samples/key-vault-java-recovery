import com.azure.core.http.rest.PagedIterable;
import com.azure.resourcemanager.keyvault.models.CreateMode;
import com.azure.resourcemanager.keyvault.models.DeletedVault;
import com.azure.resourcemanager.keyvault.models.Vault;
import com.azure.resourcemanager.keyvault.models.VaultCreateOrUpdateParameters;
import com.azure.resourcemanager.keyvault.models.VaultProperties;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.CertificateClientBuilder;
import com.azure.security.keyvault.certificates.models.CertificateContentType;
import com.azure.security.keyvault.certificates.models.CertificateOperation;
import com.azure.security.keyvault.certificates.models.CertificatePolicy;
import com.azure.security.keyvault.certificates.models.CertificateProperties;
import com.azure.security.keyvault.certificates.models.DeletedCertificate;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificateWithPolicy;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.models.CreateRsaKeyOptions;
import com.azure.security.keyvault.keys.models.DeletedKey;
import com.azure.security.keyvault.keys.models.KeyOperation;
import com.azure.security.keyvault.keys.models.KeyProperties;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.DeletedSecret;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.azure.security.keyvault.secrets.models.SecretProperties;

import java.io.IOException;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.UUID;

public class SoftDeleteSample extends KeyVaultSampleBase {

    public SoftDeleteSample() throws IOException {
        super();
    }

    static final String MIME_PKCS12 = "application/x-pkcs12";

    static final String ISSUER_UNKNOWN = "Unknown";

    /**
     * Creates a key vault which has soft delete enabled so that the
     * vault as well as all of its keys, certificates, and secrets
     * are recoverable.
     */
    public static void createSoftDeleteEnabledVault() {

        String vaultName = getRandomName("vault");

        Vault vault = azure.vaults().define(vaultName)
                .withRegion(VAULT_REGION)
                .withNewResourceGroup(RESOURCE_GROUP)
                .defineAccessPolicy()
                .forObjectId(AZURE_OBJECT_ID)
                .allowCertificateAllPermissions()
                .allowKeyAllPermissions()
                .allowSecretAllPermissions()
                .allowStorageAllPermissions()
                .attach()
                .withDeploymentEnabled()
                .withDiskEncryptionEnabled()
                .withTemplateDeploymentEnabled()
                // this vault property controls whether recovery functionality is available on the vault itself as well as
                // all keys, certificates and secrets in the vault as well

                // NOTE: This value should only None or True, setting the value to false will cause a service validation error
                //       once soft delete has been enabled on the vault it cannot be disabled
                .withSoftDeleteEnabled()
                .create();
        System.out.printf("Vault %s enabled for soft delete: %s.%n", vault.name(), vault.softDeleteEnabled());
    }

    /*
     * Enables soft delete on an existing vault.
     */
    public static void enableSoftDeleteOnExistingVault() throws InterruptedException {

        String vaultName = getRandomName("vault");

        // this vault property controls whether recovery functionality is available on the vault itself as well as
        // all keys, certificates and secrets in the vault as well
        // NOTE: This value should only None or True, setting the value to false will cause a service validation error
        //       once soft delete has been enabled on the vault it cannot be disabled

        Vault vault = createKeyVault(vaultName, RESOURCE_GROUP);

        System.out.printf("Vault %s is enabled for soft delete: enableSoftDelete = %s%n", vault.name(), vault.softDeleteEnabled());
        vault.update()
                .withSoftDeleteEnabled()
                .apply();

        System.out.printf("Updated vault %s for soft delete: enableSoftDelete = %s%n", vaultName, vault.softDeleteEnabled());
        System.out.println(azure.vaults().listByResourceGroup(RESOURCE_GROUP).stream().collect(Collectors.toList()).get(0));

    }

    private static void enableSoftDeleteForVault(Vault vault) {
        vault.update().withSoftDeleteEnabled().apply();
        System.out.printf("Updated vault %s for soft delete: enableSoftDelete = %s%n", vault.name(), vault.softDeleteEnabled());
    }


    // A sample of enumerating, retrieving, recovering and purging deleted key vaults
    public static void deletedVaultRecovery() throws Exception {

        Vault vaultToRecover = createKeyVault(getRandomName("vault"), RESOURCE_GROUP);
        enableSoftDeleteForVault(vaultToRecover);
        Vault vaultToPurge = createKeyVault(getRandomName("vault"), RESOURCE_GROUP);
        enableSoftDeleteForVault(vaultToPurge);

        System.out.printf("Created vault %s and vault %s%n", vaultToRecover.name(), vaultToPurge.name());

        azure.vaults().deleteByResourceGroup(RESOURCE_GROUP, vaultToRecover.name());
        pollOnVaultDeletion(vaultToRecover.name());
        System.out.printf("Deleted vault %s.%n", vaultToRecover.name());

        azure.vaults().deleteByResourceGroup(RESOURCE_GROUP, vaultToPurge.name());
        pollOnVaultDeletion(vaultToPurge.name());
        System.out.printf("Deleted vault %s.%n", vaultToPurge.name());

        //List the deleted vaults
        PagedIterable<DeletedVault> deletedVaults = azure.vaults().listDeleted();
        System.out.printf("Deleted vaults: %s:%s.%n", deletedVaultsToString(deletedVaults).toArray());

        //Get details of a specific vault.
        DeletedVault deletedVault = azure.vaults().getDeleted(vaultToRecover.name(), VAULT_REGION.name());
        System.out.printf("Deleted info for vault: %s %n %s %n.", deletedVault.name(), deletedVault);

        // to restore the vault simply supply the group, location, and name and set the 'create_mode' vault property to 'recover'
        // setting this property will cause other properties passed to create_or_update to be ignored and will simply
        // restore the vault in the state it was when it was deleted
        VaultProperties recoverProperties = new VaultProperties()
                .withTenantId(UUID.fromString(AZURE_TENANT_ID))
                .withCreateMode(CreateMode.RECOVER);

        VaultCreateOrUpdateParameters vaultParameters = new VaultCreateOrUpdateParameters()
                .withLocation(RESOURCE_GROUP)
                .withProperties(recoverProperties);

        Vault recoveredVault = azure.vaults().define(deletedVault.name())
                .withRegion(VAULT_REGION)
                .withExistingResourceGroup(RESOURCE_GROUP)
                .withEmptyAccessPolicy()
                .create();


        System.out.printf("Recovered vault %s%n.", recoveredVault.name());

        // list the deleted vaults again only the vault we intend to purge is still deleted
        deletedVaults = azure.vaults().listDeleted();
        System.out.printf("Deleted vaults: %s:%s.%n", deletedVaultsToString(deletedVaults).toArray());

        // Purge the last deleted vault
        azure.vaults().purgeDeleted(vaultToPurge.name(), vaultToPurge.regionName());
        System.out.printf("Purged vault: %s%n.", vaultToPurge.name());
        Thread.sleep(20000);
        // Verify no deleted vault remains
        deletedVaults = azure.vaults().listDeleted();
        System.out.printf("Deleted vaults: %s:%s.%n", deletedVaultsToString(deletedVaults).toArray());

    }

    /**
     * A sample of enumerating, retrieving, recovering and purging deleted keys from a key vault
     * @throws Exception
     */
    public static void deletedKeyRecovery() throws Exception {

        // create a vault enabling the soft delete feature
        Vault vault = createKeyVault(getRandomName("vault"), RESOURCE_GROUP);

        enableSoftDeleteForVault(vault);

        // create keys in the vault
        String keyToRecoverName = getRandomName("key");
        String keyToPurgeName = getRandomName("key");


        KeyClient keyClient = new KeyClientBuilder()
                .credential(createToken())
                .vaultUrl(vault.vaultUri())
                .buildClient();

        KeyVaultKey key = keyClient.createRsaKey(new CreateRsaKeyOptions(keyToRecoverName).
                setKeyOperations(KeyOperation.UNWRAP_KEY, KeyOperation.WRAP_KEY,
                        KeyOperation.VERIFY, KeyOperation.ENCRYPT, KeyOperation.DECRYPT));
        System.out.printf("Created key with name: %s.%n", key.getName());

        key = keyClient.createRsaKey(new CreateRsaKeyOptions(keyToPurgeName).
                setKeyOperations(KeyOperation.UNWRAP_KEY, KeyOperation.WRAP_KEY,
                        KeyOperation.VERIFY, KeyOperation.ENCRYPT, KeyOperation.DECRYPT));
        System.out.printf("Created key with name: %s.%n", key.getName());

        PagedIterable<KeyProperties> keyProperties = keyClient.listPropertiesOfKeys();
        System.out.printf("Keys: %s.%n", Arrays.toString(keyProperties.stream().map(KeyProperties::getName).toArray()));

        DeletedKey deletedKey = keyClient.beginDeleteKey(keyToRecoverName).poll().getValue();
        pollOnKeyDeletion(keyClient, keyToRecoverName);
        System.out.printf("Deleted key with name: %s.%n", deletedKey.getName());

        deletedKey = keyClient.beginDeleteKey(keyToPurgeName).poll().getValue();
        pollOnKeyDeletion(keyClient, keyToPurgeName);
        System.out.printf("Deleted key with name: %s.%n", deletedKey.getName());

        // List deleted keys
        PagedIterable<DeletedKey> deletedKeys = keyClient.listDeletedKeys();
        System.out.printf("Deleted keys: %s.%n",
                Arrays.toString(deletedKeys.stream().map(DeletedKey::getName).toArray()));

        // Recover a deleted key
        KeyVaultKey keyVaultKey = keyClient.beginRecoverDeletedKey(keyToRecoverName).poll().getValue();
        System.out.printf("Recovered key with name:%s%n", keyVaultKey.getName());

        // Purge a deleted key
        keyClient.purgeDeletedKey(keyToPurgeName);
        System.out.printf("Purged key with name: %s.%n,", keyToPurgeName);

        // List the vault keys
        keyProperties = keyClient.listPropertiesOfKeys();
        System.out.printf("Keys: %s.%n", Arrays.toString(keyProperties.stream().map(KeyProperties::getName).toArray()));

    }

    public static void deletedSecretRecovery() throws Exception {
        // create a vault enabling the soft delete feature
        Vault vault = createKeyVault(getRandomName("vault"), RESOURCE_GROUP);
        enableSoftDeleteForVault(vault);

        // create secrets in the vault
        String secretToRecoverName = getRandomName("secret");
        String secretToPurgeName = getRandomName("secret");

        SecretClient secretClient = new SecretClientBuilder()
                .credential(createToken())
                .vaultUrl(vault.vaultUri())
                .buildClient();

        KeyVaultSecret secret = secretClient.setSecret(secretToRecoverName, "secret to recover");
        System.out.printf("Create secret with name: %s.%n", secret.getName());

        secret = secretClient.setSecret(secretToPurgeName, "secret to purge");
        System.out.printf("Create secret with name: %s.%n", secret.getName());

        PagedIterable<SecretProperties> secretProperties = secretClient.listPropertiesOfSecrets();
        System.out.printf("Secrets: %s.%n",
                Arrays.toString(secretProperties.stream().map(SecretProperties::getName).toArray()));

        DeletedSecret deletedSecret = secretClient.beginDeleteSecret(secretToRecoverName).poll().getValue();
        pollOnSecretDeletion(secretClient, secretToRecoverName);
        System.out.printf("Deleted secret with name: %s%n", deletedSecret.getName());

        deletedSecret = secretClient.beginDeleteSecret(secretToPurgeName).poll().getValue();
        pollOnSecretDeletion(secretClient, secretToPurgeName);
        System.out.printf("Deleted secret with name: %s.%n", deletedSecret.getName());

        // List deleted secrets
        PagedIterable<DeletedSecret> deletedSecrets = secretClient.listDeletedSecrets();
        System.out.printf("Deleted secrets: %s.%n",
                Arrays.toString(deletedSecrets.stream().map(DeletedSecret::getName).toArray()));

        // Recover a deleted secret
        secret = secretClient.beginRecoverDeletedSecret(secretToRecoverName).poll().getValue();
        System.out.printf("Recovered secret with name: %s%n", secret.getName());

        // Purge a deleted secret
        secretClient.purgeDeletedSecret(secretToPurgeName);
        System.out.printf("Purged secret with name: %s.%n,", secretToPurgeName);

        // List the vault secrets
        secretProperties = secretClient.listPropertiesOfSecrets();
        System.out.printf("Secrets: %s.%n",
                Arrays.toString(secretProperties.stream().map(SecretProperties::getName).toArray()));

    }

    public static void deletedCertificateRecovery() throws Exception {
        // create a vault enabling the soft delete feature
        Vault vault = createKeyVault(getRandomName("vault"), RESOURCE_GROUP);
        enableSoftDeleteForVault(vault);

        // create certificates in the vault
        String certificateToRecoverName = getRandomName("certificate");
        String certificateToPurgeName = getRandomName("certificate");

        CertificateClient certificateClient = new CertificateClientBuilder()
                .credential(createToken())
                .vaultUrl(vault.vaultUri())
                .buildClient();


        SecretProperties secretProperties = new SecretProperties();
        secretProperties.setContentType(MIME_PKCS12);

        String subjectName = "CN=ManualEnrollmentJava";

        CertificatePolicy certificatePolicy = new CertificatePolicy(ISSUER_UNKNOWN, subjectName)
                .setValidityInMonths(12)
                .setContentType(CertificateContentType.PKCS12);

        CertificateOperation certificate = certificateClient
                .beginCreateCertificate(certificateToRecoverName, certificatePolicy).poll().getValue();

        System.out.printf("Created certificate with name: %s.%n", certificate.getName());

        CertificateOperation certificatePurge = certificateClient
                .beginCreateCertificate(certificateToPurgeName, certificatePolicy).poll().getValue();

        System.out.printf("Created certificate with name: %s.%n", certificatePurge.getName());

        PagedIterable<CertificateProperties> certificates = certificateClient.listPropertiesOfCertificates();
        System.out.printf("Certificates: %s.%n",
                Arrays.toString(certificates.stream().map(CertificateProperties::getName).toArray()));

        CertificateOperation deletedCertificate = certificateClient.deleteCertificateOperation(certificateToRecoverName);
        pollOnCertificateDeletion(certificateClient, certificateToRecoverName);
        System.out.printf("Deleted certificate with name: %s.%n", deletedCertificate.getName());

        deletedCertificate = certificateClient.deleteCertificateOperation(certificateToPurgeName);
        pollOnCertificateDeletion(certificateClient, certificateToPurgeName);
        System.out.printf("Deleted certificate with name: %s.%n", deletedCertificate.getName());

        // List deleted secrets
        PagedIterable<DeletedCertificate> deletedCertificates = certificateClient.listDeletedCertificates();
        System.out.printf("Deleted certificates: %s.%n",
                Arrays.toString(deletedCertificates.stream().map(DeletedCertificate::getName).toArray()));

        // Recover a deleted secret
        KeyVaultCertificateWithPolicy recoveredCertificate = certificateClient.beginRecoverDeletedCertificate(certificateToRecoverName).poll().getValue();
        System.out.printf("Recovered certificate with name: %s.%n", recoveredCertificate.getName());

        // Purge a deleted secret
        certificateClient.purgeDeletedCertificate(certificateToPurgeName);
        System.out.printf("Purged certificate with name: %s.%n,", certificateToPurgeName);

        // List the vault secrets
        certificates = certificateClient.listPropertiesOfCertificates();
        System.out.printf("Certificates: %s.%n",
                Arrays.toString(certificates.stream().map(CertificateProperties::getName).toArray()));

    }

    private static List<String> deletedVaultsToString(PagedIterable<DeletedVault> deletedVaults) {
        List<String> vaultNames = new ArrayList<>();
        for (DeletedVault vault : deletedVaults) {
            vaultNames.add(vault.name());
        }
        return vaultNames;
    }


    protected static DeletedVault pollOnVaultDeletion(String vaultName) throws Exception {
        int pendingPollCount = 0;

        while (pendingPollCount < 21) {
            DeletedVault deletedVault = azure.vaults().getDeleted(vaultName, VAULT_REGION.name());
            if (deletedVault == null) {
                Thread.sleep(10000);
                pendingPollCount++;
                continue;
            } else {
                return deletedVault;
            }

        }
        throw new Exception("Deleting vault delayed");
    }

    protected static DeletedCertificate pollOnCertificateDeletion(CertificateClient certificateClient, String certificateName)
            throws Exception {
        int pendingPollCount = 0;
        while (pendingPollCount < 21) {
            DeletedCertificate deletedCertificate = certificateClient.getDeletedCertificate(certificateName);
            if (deletedCertificate != null) {
                return deletedCertificate;
            }
            Thread.sleep(10000);
            pendingPollCount += 1;
            continue;
        }
        throw new Exception("Deleting certificate delayed");
    }

    protected static DeletedKey pollOnKeyDeletion(KeyClient keyClient, String keyName) throws Exception {
        Integer pendingPollCount = 0;
        while (pendingPollCount < 21) {
            DeletedKey deleteKey = keyClient.getDeletedKey("keyName");
            if (deleteKey != null) {
                return deleteKey;
            } else {
                Thread.sleep(10000);
                pendingPollCount++;
                continue;
            }
        }
        throw new Exception("Deleting key delayed");
    }

    protected static DeletedSecret pollOnSecretDeletion(SecretClient secretClient, String secretName) throws Exception {
        Integer pendingPollCount = 0;
        while (pendingPollCount < 50) {
            DeletedSecret deletedSecret = secretClient.getDeletedSecret(secretName);
            if (deletedSecret != null) {
                return deletedSecret;
            } else {
                Thread.sleep(10000);
                pendingPollCount++;
                continue;
            }
        }
        throw new Exception("Deleting secret delayed");
    }
}
