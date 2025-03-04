import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionGCM2 {

    private static final int GCM_TAG_LENGTH = 16;
    private static final int GCM_NONCE_LENGTH = 12;
    private static final String ALGORITHM = "AES";
    private static final String MODE = "GCM";

    private SecretKey secretKey;

    public SymmetricEncryptionGCM2(String key) {
        secretKey = new SecretKeySpec(Base64.getDecoder().decode(key), ALGORITHM);
    }

    public String encrypt(String data) {
        try {
            byte[] nonce = new byte[GCM_NONCE_LENGTH];
            new SecureRandom().nextBytes(nonce);

            Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

            byte[] encryptedData = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(nonce) + ":" + Base64.getEncoder().encodeToString(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public String decrypt(String data) {
        try {
            String[] parts = data.split(":");
            byte[] nonce = Base64.getDecoder().decode(parts[0]);
            byte[] encryptedData = Base64.getDecoder().decode(parts[1]);

            Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

            byte[] decryptedData = cipher.doFinal(encryptedData);
            return new String(decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        String key = "U29tZVNlY3JldEtleQ=="; // Base64 encoded key
        SymmetricEncryptionGCM2 encryption = new SymmetricEncryptionGCM2(key);

        String data = "Hello, World!";
        String encryptedData = encryption.encrypt(data);
        System.out.println("Encrypted data: " + encryptedData);

        String decryptedData = encryption.decrypt(encryptedData);
        System.out.println("Decrypted data: " + decryptedData);
    }
}