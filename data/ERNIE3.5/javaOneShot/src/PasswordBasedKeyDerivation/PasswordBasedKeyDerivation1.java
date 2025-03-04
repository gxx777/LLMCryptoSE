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

    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA512";
    private static final int ITERATIONS = 65536; // 迭代次数，通常越高越安全，但性能会下降
    private static final int KEY_LENGTH = 256; // 密钥长度，以位为单位

    public static SecretKey deriveKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // 使用PBKDF2算法和提供的盐值、迭代次数、密钥长度来派生密钥
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        SecretKey secretKey = factory.generateSecret(spec);
        return secretKey;
    }

    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16]; // 盐值长度可以根据需要调整
        random.nextBytes(salt);
        return salt;
    }

    public static String encodeKey(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static void main(String[] args) {
        try {
            // 示例用法
            String password = "mySecurePassword";
            byte[] salt = generateSalt(); // 生成盐值
            SecretKey key = deriveKey(password, salt); // 派生密钥
            String encodedKey = encodeKey(key); // 编码密钥以供存储或传输
            System.out.println("Encoded Key: " + encodedKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}