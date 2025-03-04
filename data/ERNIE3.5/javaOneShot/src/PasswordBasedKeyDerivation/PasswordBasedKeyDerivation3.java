import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class PasswordBasedKeyDerivation3 {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA512";
    private static final int ITERATIONS = 65536; // 足够多的迭代次数
    private static final int KEY_LENGTH = 256; // 密钥长度，以位为单位

    /**
     * 使用PBKDF2算法从给定的密码和盐值生成密钥
     *
     * @param password 密码
     * @param salt     盐值
     * @return 生成的密钥
     * @throws NoSuchAlgorithmException 如果找不到指定的算法
     * @throws InvalidKeySpecException    如果密钥规范无效
     */
    public static byte[] deriveKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
        return factory.generateSecret(spec).getEncoded();
    }

    /**
     * 将密钥编码为Base64字符串
     *
     * @param key 密钥
     * @return 编码后的Base64字符串
     */
    public static String encodeKey(byte[] key) {
        return Base64.getEncoder().encodeToString(key);
    }

    /**
     * 从Base64字符串解码密钥
     *
     * @param encodedKey 编码后的Base64字符串
     * @return 解码后的密钥
     */
    public static byte[] decodeKey(String encodedKey) {
        return Base64.getDecoder().decode(encodedKey);
    }

    // 示例用法
    public static void main(String[] args) {
        try {
            // 示例密码和盐值
            char[] password = "mySecurePassword".toCharArray();
            byte[] salt = "randomSaltValue".getBytes();

            // 派生密钥
            byte[] key = deriveKey(password, salt);

            // 编码密钥为Base64字符串
            String encodedKey = encodeKey(key);
            System.out.println("Encoded Key: " + encodedKey);

            // 解码Base64字符串为密钥
            byte[] decodedKey = decodeKey(encodedKey);
            System.out.println("Decoded Key: " + new String(decodedKey));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }
}