import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class PasswordBasedKeyDerivation4 {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 256;

    public static byte[] deriveKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        return factory.generateSecret(spec).getEncoded();
    }

    public static String deriveKeyAsString(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return Base64.getEncoder().encodeToString(deriveKey(password, salt));
    }

    public static byte[] generateSalt() {
        byte[] salt = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        return salt;
    }

    public static String generateSaltAsString() {
        return Base64.getEncoder().encodeToString(generateSalt());
    }

    public static void main(String[] args) {
        try {
            String password = "my_secret_password";
            byte[] salt = generateSalt();

            byte[] keyBytes = deriveKey(password, salt);
            String key = new String(keyBytes);

            System.out.println("Derived Key (Bytes): " + new String(keyBytes));
            System.out.println("Derived Key (String): " + key);
            System.out.println("Salt: " + new String(salt));

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }
}