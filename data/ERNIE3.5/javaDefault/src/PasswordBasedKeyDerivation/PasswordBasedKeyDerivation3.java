import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class PasswordBasedKeyDerivation3 {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA512";
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 256;

    /**
     * Derive a key from a password and a salt.
     *
     * @param password The password to derive the key from.
     * @param salt     The salt to use for key derivation.
     * @return The derived key.
     * @throws NoSuchAlgorithmException If the algorithm is not available.
     * @throws InvalidKeySpecException  If the key specification is invalid.
     */
    public static SecretKey deriveKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey secretKey = factory.generateSecret(spec);
        return secretKey;
    }

    /**
     * Generate a random salt.
     *
     * @param saltLength The length of the salt in bytes.
     * @return A randomly generated salt.
     */
    public static byte[] generateSalt(int saltLength) {
        byte[] salt = new byte[saltLength];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        return salt;
    }

    /**
     * Encode a secret key to a Base64 string.
     *
     * @param secretKey The secret key to encode.
     * @return The Base64 encoded secret key.
     */
    public static String encodeSecretKey(SecretKey secretKey) {
        byte[] encoded = secretKey.getEncoded();
        return Base64.getEncoder().encodeToString(encoded);
    }

    /**
     * Decode a Base64 string to a secret key.
     *
     * @param encodedKey The Base64 encoded secret key.
     * @return The decoded secret key.
     * @throws IllegalArgumentException If the encoded key is invalid.
     */
    public static SecretKey decodeSecretKey(String encodedKey) throws IllegalArgumentException {
        byte[] decoded = Base64.getDecoder().decode(encodedKey);
        KeySpec spec = new SecretKeySpec(decoded, 0, decoded.length, "RAW");
        SecretKeyFactory factory = null;
        try {
            factory = SecretKeyFactory.getInstance("RAW");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to create secret key factory", e);
        }
        SecretKey secretKey = null;
        try {
            secretKey = factory.generateSecret(spec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("Invalid secret key", e);
        }
        return secretKey;
    }

    public static void main(String[] args) {
        // Example usage
        try {
            // Generate a random salt
            byte[] salt = generateSalt(16);

            // Derive a key from a password and the salt
            char[] password = "mysecretpassword".toCharArray();
            SecretKey key = deriveKey(password, salt);

            // Encode the key to a Base64 string
            String encodedKey = encodeSecretKey(key);

            // Decode the Base64 string back to a secret key
            SecretKey decodedKey = decodeSecretKey(encodedKey);

            // Verify that the decoded key is the same as the original key
//            if (key.getEncoded().length == decodedKey.getEncoded().length &&
//                    java.util.Arrays.equals(key.getEncoded(), decodedKey);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
}