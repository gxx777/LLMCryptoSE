import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.spec.PBEKeySpec;

public class PasswordBasedKeyDerivation1 {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 100000;
    private static final int KEY_LENGTH = 256; // Key length in bits

    public static SecretKey deriveKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Generate a key specification from the password
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);

        // Derive the key
//        SecretKey secretKey = SecretKey.getInstance(ALGORITHM);
//        secretKey.init(keySpec);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey secretKey = factory.generateSecret(keySpec);

        return secretKey;
    }

    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16]; // Salt length should be appropriate for the chosen PBKDF2 implementation
        random.nextBytes(salt);
        return salt;
    }

    public static void main(String[] args) {
        try {
            // Generate a salt
            byte[] salt = generateSalt();

            // Assume the user enters their password as a character array
            char[] password = "mySecurePassword".toCharArray();

            // Derive the key
            SecretKey key = deriveKey(password, salt);

            // Convert the key to a byte array for further use
            byte[] keyBytes = key.getEncoded();

            // Print the key bytes (for demonstration purposes only)
            for (byte b : keyBytes) {
                System.out.format("%02x", b);
            }

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }
}