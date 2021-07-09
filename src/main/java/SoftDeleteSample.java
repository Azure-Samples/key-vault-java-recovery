import com.azure.core.http.rest.PagedIterable;
import com.azure.resourcemanager.keyvault.models.CreateMode;
import com.azure.resourcemanager.keyvault.models.DeletedVault;
import com.azure.resourcemanager.keyvault.models.Key;
import com.azure.resourcemanager.keyvault.models.Secret;
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
import com.azure.security.keyvault.keys.KeyAsyncClient;
import com.azure.security.keyvault.keys.models.CreateRsaKeyOptions;
import com.azure.security.keyvault.keys.models.DeletedKey;
import com.azure.security.keyvault.keys.models.KeyOperation;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import com.azure.security.keyvault.secrets.SecretAsyncClient;
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
        System.out.println(azure.vaults().listByResourceGroup(RESOURCE_GROUP));

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
        // restore the vault in the stat e it was when it was deleted
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
     *
     * @throws Exception
     */
    public static void deletedKeyRecovery() throws Exception {

        // create a vault enabling the soft delete feature
        Vault vault = createKeyVault(getRandomName("vault"), RESOURCE_GROUP);

        enableSoftDeleteForVault(vault);

        // create keys in the vault
        String keyToRecoverName = getRandomName("key");
        String keyToPurgeName = getRandomName("key");


        KeyAsyncClient keyAsyncClient = vault.keyClient();

        KeyVaultKey key = keyAsyncClient.createRsaKey(new CreateRsaKeyOptions(keyToRecoverName).
                setKeyOperations(KeyOperation.UNWRAP_KEY, KeyOperation.WRAP_KEY,
                        KeyOperation.VERIFY, KeyOperation.ENCRYPT, KeyOperation.DECRYPT)).block();
        System.out.printf("Create key %s.%n", key.getId().toString());

        key = keyAsyncClient.createRsaKey(new CreateRsaKeyOptions(keyToPurgeName).
                setKeyOperations(KeyOperation.UNWRAP_KEY, KeyOperation.WRAP_KEY,
                        KeyOperation.VERIFY, KeyOperation.ENCRYPT, KeyOperation.DECRYPT)).block();
        System.out.printf("Create key %s.%n", key.getId());

        PagedIterable<Key> keys = vault.keys().list();
        System.out.printf("Keys: %s.%n", Arrays.toString(keys.stream().collect(Collectors.toList()).toArray()));

        DeletedKey deletedKey = keyAsyncClient.beginDeleteKey(keyToRecoverName).getSyncPoller().poll().getValue();
        pollOnKeyDeletion(keyAsyncClient, keyToRecoverName);
        System.out.printf("Deleted key %s.%n", deletedKey.toString());

        deletedKey = keyAsyncClient.beginDeleteKey(keyToPurgeName).getSyncPoller().poll().getValue();
        pollOnKeyDeletion(keyAsyncClient, keyToPurgeName);
        System.out.printf("Deleted key %s.%n", deletedKey.toString());

        // List deleted keys
        List<DeletedKey> deletedKeys = keyAsyncClient.listDeletedKeys().collectList().block();
        System.out.printf("Deleted keys %s.%n", Arrays.toString(deletedKeys.toArray()));

        // Recover a deleted key
        KeyVaultKey keyVaultKey = keyAsyncClient.beginRecoverDeletedKey(keyToRecoverName).getSyncPoller().poll().getValue();
        System.out.printf("Recovered key %s%n", keyVaultKey.toString());

        // Purge a deleted key
        keyAsyncClient.purgeDeletedKey(keyToPurgeName).block();
        System.out.printf("Purged key %s.%n,", keyToPurgeName);

        // List the vault keys
        keys = vault.keys().list();
        System.out.printf("Keys: %s.%n", Arrays.toString(keys.stream().collect(Collectors.toList()).toArray()));

    }

    public static void deletedSecretRecovery() throws Exception {
        // create a vault enabling the soft delete feature
        Vault vault = createKeyVault(getRandomName("vault"), RESOURCE_GROUP);
        enableSoftDeleteForVault(vault);

        // create secrets in the vault
        String secretToRecoverName = getRandomName("secret");
        String secretToPurgeName = getRandomName("secret");

        SecretAsyncClient secretAsyncClient = vault.secretClient();

        KeyVaultSecret secret = secretAsyncClient.setSecret(secretToRecoverName, "secret to recover").block();
        System.out.printf("Create secret %s.%n", secret.toString());

        secret = secretAsyncClient.setSecret(secretToPurgeName, "secret to purge").block();
        System.out.printf("Create secret %s.%n", secret.toString());

        List<Secret> secrets = vault.secrets().list().stream().collect(Collectors.toList());
        System.out.printf("Secret: %s.%n", Arrays.toString(secrets.toArray()));

        DeletedSecret deletedSecret = secretAsyncClient.beginDeleteSecret(secretToRecoverName).getSyncPoller().poll().getValue();
        pollOnSecretDeletion(secretAsyncClient, secretToRecoverName);
        System.out.printf("Deleted key %s.%n", deletedSecret);

        deletedSecret = secretAsyncClient.beginDeleteSecret(secretToPurgeName).getSyncPoller().poll().getValue();
        pollOnSecretDeletion(secretAsyncClient, secretToPurgeName);
        System.out.printf("Deleted key %s.%n", deletedSecret);

        // List deleted secrets
        List<DeletedSecret> deletedSecrets = secretAsyncClient.listDeletedSecrets().collectList().block();
        System.out.printf("Deleted secret %s.%n", Arrays.toString(deletedSecrets.toArray()));

        // Recover a deleted secret
        secret = secretAsyncClient.beginRecoverDeletedSecret(secretToRecoverName).getSyncPoller().poll().getValue();
        System.out.printf("Recovered secret %s%n", secret.toString());

        // Purge a deleted secret
        secretAsyncClient.purgeDeletedSecret(secretToPurgeName).block();
        System.out.printf("Purged secret %s.%n,", secretToPurgeName);

        // List the vault secrets
        secrets = vault.secrets().list().stream().collect(Collectors.toList());
        System.out.printf("Secret: %s.%n", Arrays.toString(secrets.toArray()));

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

        System.out.printf("Create certificate %s.%n", certificate.toString());

        CertificateOperation certificatePurge = certificateClient
                .beginCreateCertificate(certificateToPurgeName, certificatePolicy).poll().getValue();

        System.out.printf("Create certificate %s.%n", certificatePurge.toString());

        List<CertificateProperties> certificates = certificateClient.listPropertiesOfCertificates().stream().collect(Collectors.toList());
        System.out.printf("Certificate: %s.%n", Arrays.toString(certificates.toArray()));

        CertificateOperation deletedCertificate = certificateClient.deleteCertificateOperation(certificateToRecoverName);
        pollOnCertificateDeletion(certificateClient, certificateToRecoverName);
        System.out.printf("Deleted certificate %s.%n", deletedCertificate.toString());

        deletedCertificate = certificateClient.deleteCertificateOperation(certificateToPurgeName);
        pollOnCertificateDeletion(certificateClient, certificateToPurgeName);
        System.out.printf("Deleted certificate %s.%n", deletedCertificate.toString());

        // List deleted secrets
        List<DeletedCertificate> deletedCertificates = certificateClient.listDeletedCertificates().stream().collect(Collectors.toList());
        System.out.printf("Deleted certificate %s.%n", Arrays.toString(deletedCertificates.toArray()));

        // Recover a deleted secret
        KeyVaultCertificateWithPolicy recoveredCertificate = certificateClient.beginRecoverDeletedCertificate(certificateToRecoverName).poll().getValue();
        System.out.printf("Recovered certificate %s.%n", recoveredCertificate.getPolicy().toString());

        // Purge a deleted secret
        certificateClient.purgeDeletedCertificate(certificateToPurgeName);
        System.out.printf("Purged certificate %s.%n,", certificateToPurgeName);

        // List the vault secrets
        certificates = certificateClient.listPropertiesOfCertificates().stream().collect(Collectors.toList());
        System.out.printf("Certificates: %s.%n", Arrays.toString(certificates.toArray()));

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

    protected static DeletedKey pollOnKeyDeletion(KeyAsyncClient keyAsyncClient, String keyName) throws Exception {
        Integer pendingPollCount = 0;
        while (pendingPollCount < 21) {
            DeletedKey deleteKey = keyAsyncClient.getDeletedKeyWithResponse(keyName).block().getValue();
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

    protected static DeletedSecret pollOnSecretDeletion(SecretAsyncClient secretAsyncClient, String secretName) throws Exception {
        Integer pendingPollCount = 0;
        while (pendingPollCount < 50) {
            DeletedSecret deletedSecret = secretAsyncClient.getDeletedSecret(secretName).block();
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
