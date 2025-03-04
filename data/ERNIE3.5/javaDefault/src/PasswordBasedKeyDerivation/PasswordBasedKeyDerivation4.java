import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class PasswordBasedKeyDerivation4 {

    // 盐的随机生成器
    private static final SecureRandom random = new SecureRandom();

    // PBKDF2算法的迭代次数，应该足够大以确保密钥的安全性
    private static final int ITERATIONS = 65536;

    // PBKDF2算法的密钥长度，以位为单位
    private static final int KEY_LENGTH = 256;

    // 生成密钥
    public static SecretKeySpec generateKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // PBKDF2算法，使用HMAC-SHA512作为伪随机函数
        String algorithm = "PBKDF2WithHmacSHA512";

        // 使用PBKDF2算法和提供的参数生成密钥
        SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), algorithm);
    }

    // 生成随机盐
    public static byte[] generateSalt(int saltSize) {
        byte[] salt = new byte[saltSize];
        random.nextBytes(salt);
        return salt;
    }

    // 派生密钥的简化方法，包含生成盐和密钥
    public static SecretKeySpec deriveKey(String password, int saltSize) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = generateSalt(saltSize);
        return generateKey(password, salt);
    }

    // 示例：派生一个密钥并打印其Base64编码
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String password = "MySecurePassword";
        int saltSize = 16; // 常见的盐大小，可以根据需要调整

        SecretKeySpec key = deriveKey(password, saltSize);

        // 打印Base64编码的密钥
        String base64Key = Base64.getEncoder().encodeToString(key.getEncoded());
        System.out.println("Derived Key (Base64): " + base64Key);
    }
}