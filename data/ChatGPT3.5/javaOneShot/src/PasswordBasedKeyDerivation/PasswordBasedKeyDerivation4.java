import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordBasedKeyDerivation4 {

    private static final int ITERATIONS = 10000; // Recommended minimum iterations is 10000
    private static final int KEY_LENGTH = 256; // Key length in bits
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";

    public static byte[] deriveKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        return keyFactory.generateSecret(keySpec).getEncoded();
    }

    public static void main(String[] args) {
        String password = "mySecurePassword";
        byte[] salt = generateRandomSalt();
        try {
            byte[] derivedKey = deriveKey(password, salt);
            System.out.println("Derived key: " + bytesToHex(derivedKey));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    private static byte[] generateRandomSalt() {
        byte[] salt = new byte[16]; // 16 bytes salt
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}