import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class PasswordBasedKeyDerivation1 {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 65536; // 你可以根据需要增加这个值
    private static final int KEY_LENGTH = 256; // 派生出的密钥长度

    public static SecretKey deriveKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        return keyFactory.generateSecret(keySpec);
    }

    public static void main(String[] args) {
        try {
            // 示例密码和盐
            String password = "mySecurePassword";
            byte[] salt = generateRandomSalt();

            // 派生密钥
            SecretKey secretKey = deriveKey(password, salt);

            // 打印结果（仅用于示例，实际中不应直接打印密钥）
            System.out.println("Derived Key (Base64): " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));
            System.out.println("Salt (Base64): " + Base64.getEncoder().encodeToString(salt));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] generateRandomSalt() {
        byte[] salt = new byte[16]; // 盐的长度可以根据需要调整
        new SecureRandom().nextBytes(salt);
        return salt;
    }
}