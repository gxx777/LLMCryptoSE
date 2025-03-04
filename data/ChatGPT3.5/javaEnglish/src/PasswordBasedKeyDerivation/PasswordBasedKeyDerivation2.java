import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class PasswordBasedKeyDerivation2 {

    public static byte[] deriveKey(String password, byte[] salt, int keyLength, int iterations) {
        byte[] key = null;

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength * 8);
            key = factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return key;
    }

    public static void main(String[] args) {
        String password = "MySecretPassword";
        byte[] salt = generateSalt(); // You can generate a random salt using a secure random number generator
        int keyLength = 16; // Key length in bytes
        int iterations = 10000; // Number of iterations

        byte[] key = deriveKey(password, salt, keyLength, iterations);

        System.out.println("Derived key: " + bytesToHex(key));
    }

    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}