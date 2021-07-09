import com.azure.core.credential.TokenCredential;
import com.azure.core.http.policy.HttpLogDetailLevel;
import com.azure.core.http.policy.HttpLogOptions;
import com.azure.core.management.AzureEnvironment;
import com.azure.core.management.Region;
import com.azure.core.management.profile.AzureProfile;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.resourcemanager.AzureResourceManager;
import com.azure.resourcemanager.keyvault.models.Vault;

public class KeyVaultSampleBase {

    protected static AzureResourceManager azure;

    protected static final Region VAULT_REGION = Region.US_WEST_CENTRAL;
    protected static final String AZURE_CLIENT_ID = System.getProperty("AZURE_CLIENT_ID");
    protected static final String AZURE_CLIENT_SECRET = System.getProperty("AZURE_CLIENT_SECRET");
    protected static final String AZURE_TENANT_ID = System.getProperty("AZURE_TENANT_ID");
    protected static final String AZURE_OBJECT_ID = System.getProperty("AZURE_OBJECT_ID");
    protected static final String RESOURCE_GROUP = System.getProperty("AZURE_RESOURCE_GROUP");
    protected static final String AZURE_SUBSCRIPTION_ID = System.getProperty("AZURE_SUBSCRIPTION_ID");

    static {
        authenticateToAzure();
    }

    protected static String getRandomName(String name) {
        return azure.resourceGroups().manager().internalContext().randomResourceName(name, 20);
    }

    //This creates a non-soft-delete enabled key vault.
    protected static Vault createKeyVault(String vaultName, String resourceGroupName) throws InterruptedException {

        System.out.printf("Creating a new vault %s...%n", vaultName);

        Vault vault = azure.vaults().define(vaultName)
                .withRegion(VAULT_REGION)
                .withExistingResourceGroup(resourceGroupName)
                .defineAccessPolicy()
                .forObjectId(AZURE_OBJECT_ID)
                .allowKeyAllPermissions()
                .allowSecretAllPermissions()
                .allowCertificateAllPermissions()
                .allowStorageAllPermissions()
                .attach()
                .withDeploymentEnabled()
                .withDiskEncryptionEnabled()
                .withTemplateDeploymentEnabled()
                .create();

        Thread.sleep(20000);
        System.out.println("Vault created");
        return vault;
    }

    protected static TokenCredential createToken() {
        return new ClientSecretCredentialBuilder()
                .clientSecret(AZURE_CLIENT_SECRET)
                .tenantId(AZURE_TENANT_ID)
                .clientId(AZURE_CLIENT_ID)
                .build();
    }

    private static void authenticateToAzure() {
        // Authentication for general Azure service
        azure = AzureResourceManager
                .configure().withLogOptions(new HttpLogOptions().setLogLevel(HttpLogDetailLevel.BASIC))
                .authenticate(createToken(), new AzureProfile(AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID, AzureEnvironment.AZURE))
                .withSubscription(AZURE_SUBSCRIPTION_ID);
    }

}
