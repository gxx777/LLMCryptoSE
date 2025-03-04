import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordBasedKeyDerivation4 {

    public static SecretKey generateKey(char[] password, byte[] salt, int iterations, int keyLength) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKey key = factory.generateSecret(spec);
        spec.clearPassword();
        return key;
    }

    public static void main(String[] args) {
        String password = "myPassword";
        byte[] salt = {0, 1, 2, 3, 4, 5, 6, 7};
        int iterations = 10000;
        int keyLength = 256;

        try {
            SecretKey key = generateKey(password.toCharArray(), salt, iterations, keyLength);
            System.out.println("Generated key: " + key);
        } catch (Exception e) {
            System.err.println("Error generating key: " + e.getMessage());
        }
    }
}