import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class PasswordBasedKeyDerivation3 {

    private static final String SALT = "random_salt_value"; // Replace with a random salt value
    private static final int ITERATIONS = 100000; // Number of iterations for PBKDF2
    private static final int KEY_LENGTH = 256; // Key length in bits

    public static byte[] deriveKey(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Convert the password to a character array
        char[] passwordChars = password.toCharArray();

        // Generate a random salt
        byte[] salt = SALT.getBytes();

        // Derive the key using PBKDF2
        KeySpec keySpec = new PBEKeySpec(passwordChars, salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        return keyFactory.generateSecret(keySpec).getEncoded();
    }

    public static String getBase64EncodedKey(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = deriveKey(password);
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    public static void main(String[] args) {
        try {
            String password = "my_secret_password";
            byte[] keyBytes = deriveKey(password);
            System.out.println("Derived Key (Bytes): " + new String(keyBytes));

            String base64EncodedKey = getBase64EncodedKey(password);
            System.out.println("Derived Key (Base64): " + base64EncodedKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }
}