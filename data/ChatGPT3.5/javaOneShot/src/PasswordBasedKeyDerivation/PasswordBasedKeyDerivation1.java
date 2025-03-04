import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class PasswordBasedKeyDerivation1 {

    private static final int ITERATIONS = 10000; // Recommended minimum value
    private static final int KEY_LENGTH = 256;

    public SecretKey deriveKey(String password, byte[] salt) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
            SecretKey key = factory.generateSecret(spec);
            return key;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    // Example usage
    public static void main(String[] args) {
        PasswordBasedKeyDerivation1 keyDerivation = new PasswordBasedKeyDerivation1();
        String password = "mySecurePassword";
        byte[] salt = new byte[16]; // Generate a random salt for each password
        SecretKey derivedKey = keyDerivation.deriveKey(password, salt);
        System.out.println("Derived key: " + derivedKey);
    }
}