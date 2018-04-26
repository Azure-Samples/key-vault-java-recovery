import com.microsoft.azure.keyvault.models.*;
import com.microsoft.azure.keyvault.requests.CreateCertificateRequest;
import com.microsoft.azure.keyvault.webkey.JsonWebKeyType;
import com.microsoft.azure.management.keyvault.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

public class SoftDeleteSample extends KeyVaultSampleBase {

    public SoftDeleteSample() throws IOException{
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
        System.out.println(azure.vaults().listByResourceGroup(RESOURCE_GROUP).get(0));

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
        List<DeletedVault> deletedVaults = azure.vaults().listDeleted();
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
                .withCreateMode(CreateMode.RECOVER)
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

        KeyBundle key = keyVaultClient.createKey(vault.vaultUri(), keyToRecoverName, JsonWebKeyType.RSA);
        System.out.printf("Create key %s.%n", key.keyIdentifier().toString());

        key = keyVaultClient.createKey(vault.vaultUri(), keyToPurgeName, JsonWebKeyType.RSA);
        System.out.printf("Create key %s.%n", key.keyIdentifier().toString());

        List<KeyItem> keys = keyVaultClient.listKeys(vault.vaultUri());
        System.out.printf("Keys: %s.%n", Arrays.toString(keys.toArray()));

        DeletedKeyBundle deletedKey = keyVaultClient.deleteKey(vault.vaultUri(), keyToRecoverName);
        pollOnKeyDeletion(vault.vaultUri(), keyToRecoverName);
        System.out.printf("Deleted key %s.%n", deletedKey.toString());

        deletedKey = keyVaultClient.deleteKey(vault.vaultUri(), keyToPurgeName);
        pollOnKeyDeletion(vault.vaultUri(), keyToPurgeName);
        System.out.printf("Deleted key %s.%n", deletedKey.toString());

        // List deleted keys
        List<DeletedKeyItem> deletedKeys = keyVaultClient.getDeletedKeys(vault.vaultUri());
        System.out.printf("Deleted keys %s.%n", Arrays.toString(deletedKeys.toArray()));

        // Recover a deleted key
        key = keyVaultClient.recoverDeletedKey(vault.vaultUri(), keyToRecoverName);
        System.out.printf("Recovered key %s%n", key.toString());

        // Purge a deleted key
        keyVaultClient.purgeDeletedKey(vault.vaultUri(), keyToPurgeName);
        System.out.printf("Purged key %s.%n,", keyToPurgeName);

        // List the vault keys
        keys = keyVaultClient.listKeys(vault.vaultUri());
        System.out.printf("Keys: %s.%n", Arrays.toString(keys.toArray()));

    }

    public static void deletedSecretRecovery() throws Exception {
        // create a vault enabling the soft delete feature
        Vault vault = createKeyVault(getRandomName("vault"), RESOURCE_GROUP);
        enableSoftDeleteForVault(vault);

        // create secrets in the vault
        String secretToRecoverName = getRandomName("secret");
        String secretToPurgeName = getRandomName("secret");

        SecretBundle secret = keyVaultClient.setSecret(vault.vaultUri(), secretToRecoverName, "secret to recover");
        System.out.printf("Create secret %s.%n", secret.toString());


        secret = keyVaultClient.setSecret(vault.vaultUri(), secretToPurgeName, "secret to purge");
        System.out.printf("Create secret %s.%n", secret.toString());

        List<SecretItem> secrets = keyVaultClient.getSecrets(vault.vaultUri());
        System.out.printf("Secret: %s.%n", Arrays.toString(secrets.toArray()));

        DeletedSecretBundle deletedSecret = keyVaultClient.deleteSecret(vault.vaultUri(), secretToRecoverName);
        pollOnSecretDeletion(vault.vaultUri(), secretToRecoverName);
        System.out.printf("Deleted secret %s.%n", deletedSecret.toString());

        deletedSecret = keyVaultClient.deleteSecret(vault.vaultUri(), secretToPurgeName);
        pollOnSecretDeletion(vault.vaultUri(), secretToPurgeName);
        System.out.printf("Deleted secret %s.%n", deletedSecret.toString());

        // List deleted secrets
        List<DeletedSecretItem> deletedSecrets = keyVaultClient.getDeletedSecrets(vault.vaultUri());
        System.out.printf("Deleted secret %s.%n", Arrays.toString(deletedSecrets.toArray()));

        // Recover a deleted secret
        secret = keyVaultClient.recoverDeletedSecret(vault.vaultUri(), secretToRecoverName);
        System.out.printf("Recovered secret %s%n", secret.toString());

        // Purge a deleted secret
        keyVaultClient.purgeDeletedSecret(vault.vaultUri(), secretToPurgeName);
        System.out.printf("Purged secret %s.%n,", secretToPurgeName);

        // List the vault secrets
        secrets = keyVaultClient.listSecrets(vault.vaultUri());
        System.out.printf("Secrets: %s.%n", Arrays.toString(secrets.toArray()));

    }

    public static void deletedCertificateRecovery() throws Exception {
        // create a vault enabling the soft delete feature
        Vault vault = createKeyVault(getRandomName("vault"), RESOURCE_GROUP);
        enableSoftDeleteForVault(vault);

        // create certificates in the vault
        String certificateToRecoverName = getRandomName("certificate");
        String certificateToPurgeName = getRandomName("certificate");

        SecretProperties secretProperties = new SecretProperties();
        secretProperties.withContentType(MIME_PKCS12);

        X509CertificateProperties x509Properties = new X509CertificateProperties();
        String subjectName = "CN=ManualEnrollmentJava";
        x509Properties.withSubject(subjectName);
        x509Properties.withValidityInMonths(12);

        // Set issuer to "Unknown"
        IssuerParameters issuerParameters = new IssuerParameters();
        issuerParameters.withName(ISSUER_UNKNOWN);

        CertificatePolicy certificatePolicy = new CertificatePolicy()
                .withSecretProperties(secretProperties)
                .withIssuerParameters(issuerParameters)
                .withX509CertificateProperties(x509Properties);

        CertificateOperation certificate = keyVaultClient.createCertificate(
                new CreateCertificateRequest
                        .Builder(vault.vaultUri(), certificateToRecoverName)
                        .withPolicy(certificatePolicy)
                        .build());

        System.out.printf("Create certificate %s.%n", certificate.toString());

        CertificateOperation certificatePurge = keyVaultClient.createCertificate(
                new CreateCertificateRequest
                        .Builder(vault.vaultUri(), certificateToPurgeName)
                        .withPolicy(certificatePolicy)
                        .build());
        System.out.printf("Create certificate %s.%n", certificatePurge.toString());

        List<CertificateItem> certificates = keyVaultClient.getCertificates(vault.vaultUri());
        System.out.printf("Certificate: %s.%n", Arrays.toString(certificates.toArray()));

        DeletedCertificateBundle deletedCertificate = keyVaultClient.deleteCertificate(vault.vaultUri(), certificateToRecoverName);
        pollOnCertificateDeletion(vault.vaultUri(), certificateToRecoverName);
        System.out.printf("Deleted certificate %s.%n", deletedCertificate.toString());

        deletedCertificate = keyVaultClient.deleteCertificate(vault.vaultUri(), certificateToPurgeName);
        pollOnCertificateDeletion(vault.vaultUri(), certificateToPurgeName);
        System.out.printf("Deleted certificate %s.%n", deletedCertificate.toString());

        // List deleted secrets
        List<DeletedCertificateItem> deletedCertificates = keyVaultClient.getDeletedCertificates(vault.vaultUri());
        System.out.printf("Deleted certificate %s.%n", Arrays.toString(deletedCertificates.toArray()));

        // Recover a deleted secret
        CertificateBundle recoveredCertificate = keyVaultClient.recoverDeletedCertificate(vault.vaultUri(), certificateToRecoverName);
        System.out.printf("Recovered certificate %s.%n", recoveredCertificate.toString());

        // Purge a deleted secret
        keyVaultClient.purgeDeletedCertificate(vault.vaultUri(), certificateToPurgeName);
        System.out.printf("Purged certificate %s.%n,", certificateToPurgeName);

        // List the vault secrets
        certificates = keyVaultClient.listCertificates(vault.vaultUri());
        System.out.printf("Certificates: %s.%n", Arrays.toString(certificates.toArray()));

    }

    private static List<String> deletedVaultsToString(List<DeletedVault> deletedVaults) {
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
            if (deletedVault == null ) {
                Thread.sleep(10000);
                pendingPollCount++;
                continue;
            } else {
                return deletedVault;
            }

        }
        throw new Exception("Deleting vault delayed");
    }

    protected static DeletedCertificateBundle pollOnCertificateDeletion(String vaultBaseUrl, String certificateName)
            throws Exception {
        int pendingPollCount = 0;
        while (pendingPollCount < 21) {
            DeletedCertificateBundle certificateBundle = keyVaultClient.getDeletedCertificate(vaultBaseUrl,
                    certificateName);
            if (certificateBundle == null) {
                Thread.sleep(10000);

                pendingPollCount += 1;
                continue;
            } else {
                return certificateBundle;
            }
        }
        throw new Exception("Deleting certificate delayed");
    }

    protected static DeletedKeyBundle pollOnKeyDeletion(String vaultBaseUrl, String keyName) throws Exception {
        int pendingPollCount = 0;
        while (pendingPollCount < 21) {
            DeletedKeyBundle deletedKeyBundle = keyVaultClient.getDeletedKey(vaultBaseUrl, keyName);
            if (deletedKeyBundle == null) {
                Thread.sleep(10000);

                pendingPollCount += 1;
                continue;
            } else {
                return deletedKeyBundle;
            }
        }
        throw new Exception("Deleting key delayed");
    }

    protected static DeletedSecretBundle pollOnSecretDeletion(String vaultBaseUrl, String secretName) throws Exception {
        int pendingPollCount = 0;
        while (pendingPollCount < 50) {
            DeletedSecretBundle deletedSecretBundle = keyVaultClient.getDeletedSecret(vaultBaseUrl, secretName);
            if (deletedSecretBundle == null) {
                Thread.sleep(10000);

                pendingPollCount += 1;
                continue;
            } else {
                return deletedSecretBundle;
            }
        }
        throw new Exception("Deleting secret delayed");
    }
}
