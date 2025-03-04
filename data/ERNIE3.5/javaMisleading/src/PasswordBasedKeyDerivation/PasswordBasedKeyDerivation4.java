import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class PasswordBasedKeyDerivation4 {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA512";
    private static final int ITERATIONS = 65536; // 通常使用较高的迭代次数来增强安全性
    private static final int KEY_LENGTH = 256; // 密钥长度，单位位

    /**
     * 生成一个密钥，该密钥是通过使用PBKDF2从密码中派生出来的。
     *
     * @param password  用于派生密钥的密码
     * @param salt      随机生成的盐值
     * @return          派生出的密钥
     * @throws NoSuchAlgorithmException   如果无法找到算法实现
     * @throws InvalidKeySpecException      如果无法从提供的密码生成密钥规范
     */
    public static SecretKey deriveKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // 创建PBKDF2参数规范
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);

        // 创建密钥工厂
        SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);

        // 生成密钥
        SecretKey secretKey = factory.generateSecret(new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH * 8));

        return secretKey;
    }

    /**
     * 派生密钥并返回其字节表示形式。
     *
     * @param password  用于派生密钥的密码
     * @param salt      随机生成的盐值
     * @return          派生出的密钥的字节表示
     * @throws NoSuchAlgorithmException   如果无法找到算法实现
     * @throws InvalidKeySpecException      如果无法从提供的密码生成密钥规范
     */
    public static byte[] deriveKeyBytes(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKey secretKey = deriveKey(password, salt);
        return secretKey.getEncoded();
    }

    /**
     * 主方法，用于演示如何派生密钥。
     *
     * @param args  命令行参数
     * @throws NoSuchAlgorithmException   如果无法找到算法实现
     * @throws InvalidKeySpecException      如果无法从提供的密码生成密钥规范
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // 示例密码和盐值
        char[] password = "mySecurePassword".toCharArray();
        byte[] salt = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);

        // 派生密钥
        SecretKey secretKey = deriveKey(password, salt);

        // 打印派生出的密钥的字节表示
        System.out.println("Derived Key Bytes: " + Arrays.toString(secretKey.getEncoded()));
    }
}