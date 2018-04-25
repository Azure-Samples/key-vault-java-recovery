import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationException;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.credentials.ApplicationTokenCredentials;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import com.microsoft.azure.management.Azure;
import com.microsoft.azure.management.keyvault.Vault;
import com.microsoft.azure.management.resources.fluentcore.arm.Region;
import com.microsoft.azure.management.resources.fluentcore.utils.SdkContext;
import com.microsoft.rest.LogLevel;
import com.microsoft.rest.credentials.ServiceClientCredentials;

import java.net.MalformedURLException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class KeyVaultSampleBase {

    protected static KeyVaultClient keyVaultClient;
    protected static Azure azure;

    protected static final Region VAULT_REGION = Region.US_WEST;
    protected static final String AZURE_CLIENT_ID = System.getenv("AZURE_CLIENT_ID");
    protected static final String AZURE_OBJECT_ID = System.getenv("AZURE_OBJECT_ID");
    protected static final String AZURE_CLIENT_SECRET = System.getenv("AZURE_CLIENT_SECRET");
    protected static final String AZURE_TENANT_ID = System.getenv("AZURE_TENANT_ID");
    protected static final String RESOURCE_GROUP = System.getenv("AZURE_RESOURCE_GROUP");

    static {
        authenticateToAzure();
        keyVaultClient = new KeyVaultClient(createCredentials());
    }

    protected static String getRandomName(String name) {
        return SdkContext.randomResourceName(name, 20);
    }

    //This creates a non-soft-delete enabled key vault.
    protected static Vault createKeyVault(String vaultName, String resourceGroupName) throws InterruptedException {

        System.out.printf("Creating a new vault %s...%n", vaultName);

        Vault vault = azure.vaults().define(vaultName)
                .withRegion(VAULT_REGION)
                .withExistingResourceGroup(resourceGroupName)
                .defineAccessPolicy()
                    //The object ID that's passed in for the vault needs to be the object ID of the Service Principal
                    .forObjectId(AZURE_OBJECT_ID)
                    .allowKeyAllPermissions()
                    .allowSecretAllPermissions()
                    .allowCertificateAllPermissions()
                    .attach()
                .withDeploymentEnabled()
                .withDiskEncryptionEnabled()
                .withTemplateDeploymentEnabled()
                .create();

        Thread.sleep(20000);
        System.out.println("Vault created");
        return vault;
    }

    /**
     * Creates a new KeyVaultCredential based on the access token obtained.
     *
     * @return
     */
    private static ServiceClientCredentials createCredentials() {
        return new KeyVaultCredentials() {

            // Callback that supplies the token type and access token on request.
            @Override
            public String doAuthenticate(String authorization, String resource, String scope) {

                AuthenticationResult authResult;
                try {
                    authResult = getAccessToken(authorization, resource);
                    return authResult.getAccessToken();
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return "";
            }
        };
    }


    // Private helper method that gets the access token for the authorization and
    // resource depending on which variables are supplied in the environment.
    private static AuthenticationResult getAccessToken(String authorization, String resource)
            throws InterruptedException, ExecutionException, MalformedURLException {

        String clientId = System.getenv("AZURE_CLIENT_ID");
        String clientKey = System.getenv("AZURE_CLIENT_SECRET");

        AuthenticationResult result = null;

        // Starts a service to fetch access token.
        ExecutorService service = null;
        try {
            service = Executors.newFixedThreadPool(1);
            AuthenticationContext context = new AuthenticationContext(authorization, false, service);

            Future<AuthenticationResult> future = null;

            // Acquires token based on client ID and client secret.
            if (clientKey != null && clientKey != null) {
                ClientCredential credentials = new ClientCredential(clientId, clientKey);
                future = context.acquireToken(resource, credentials, null);
            }

            result = future.get();
        } finally {
            service.shutdown();
        }

        if (result == null) {
            throw new RuntimeException("Authentication results were null.");
        }
        return result;
    }

    private static void authenticateToAzure() {
        // Authentication for general Azure service
        ApplicationTokenCredentials credentials = new ApplicationTokenCredentials(System.getenv("AZURE_CLIENT_ID"),
                System.getenv("AZURE_TENANT_ID"), System.getenv("AZURE_CLIENT_SECRET"), AzureEnvironment.AZURE);

        try {
            azure = Azure.configure().withLogLevel(LogLevel.BASIC).authenticate(credentials).withDefaultSubscription();

        } catch (Exception e) {
            e.printStackTrace();
            throw new AuthenticationException(
                    "Error authenticating to Azure - check your credentials in your environment.");
        }
    }

}
