import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordBasedKeyDerivation3 {

    public static SecretKey deriveKey(String password, byte[] salt, int iterationCount, int keyLength) {
        try {
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength*8);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return keyFactory.generateSecret(pbeKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        String password = "myStrongPassword";
        byte[] salt = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
        int iterationCount = 10000;
        int keyLength = 16;

        SecretKey key = deriveKey(password, salt, iterationCount, keyLength);
        System.out.println(key.getEncoded());
    }
}