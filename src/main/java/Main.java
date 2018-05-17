public class Main {
    public static void main(String[] args) throws Exception {
        runAllSamples();
    }

    private static void runAllSamples() throws Exception {
        //BackupRestoreSample.backupRestoreSecret();
        BackupRestoreSample.backupRestoreKey();
        SoftDeleteSample.createSoftDeleteEnabledVault();
        SoftDeleteSample.deletedVaultRecovery();
        SoftDeleteSample.deletedSecretRecovery();
        SoftDeleteSample.deletedCertificateRecovery();
    }
}