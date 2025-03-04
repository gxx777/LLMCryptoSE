import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;

public class PasswordBasedKeyDerivation4 {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";

    public static SecretKey deriveKey(String password, byte[] salt, int iterations, int keyLength) throws Exception {
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        return secretKeyFactory.generateSecret(keySpec);
    }

    public static void main(String[] args) {
        try {
            String password = "MyPassword123";
            byte[] salt = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05};
            int iterations = 10000;
            int keyLength = 256;

            SecretKey secretKey = deriveKey(password, salt, iterations, keyLength);

            System.out.println("Derived key: " + secretKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}