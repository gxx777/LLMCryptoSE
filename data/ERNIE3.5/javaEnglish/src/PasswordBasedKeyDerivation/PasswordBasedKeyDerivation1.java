import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class PasswordBasedKeyDerivation1 {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 256;

    public static byte[] deriveKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        return secretKeyFactory.generateSecret(keySpec).getEncoded();
    }

    public static void main(String[] args) {
        try {
            // Example usage
            String password = "my_password";
            byte[] salt = new byte[16]; // Generate a random salt of appropriate length

            // Derive the key
            byte[] derivedKey = deriveKey(password, salt);

            // Use the derived key for encryption/decryption purposes

            // Note: The salt should be securely stored alongside the encrypted data

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }
}