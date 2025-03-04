import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
//import java.security.;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class PasswordBasedKeyDerivation4 {

    // 盐的随机生成器
    private static final SecureRandom RANDOM = new SecureRandom();

    // 密钥派生函数的迭代次数，应该是一个较大的值以增加计算成本
    private static final int ITERATIONS = 65536;

    // 密钥长度，例如AES密钥长度可以是128, 192或256位
    private static final int KEY_LENGTH = 256;

    // 用于生成密钥的算法名称，这里使用PBKDF2WithHmacSHA512
    private static final String ALGORITHM = "PBKDF2WithHmacSHA512";

    /**
     * 生成密钥
     *
     * @param password 口令
     * @return 生成的密钥
     * @throws NoSuchAlgorithmException 如果找不到指定的算法
     * @throws InvalidKeySpecException 如果密钥规范无效
     */
    public static SecretKeySpec generateKey(char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // 随机生成盐
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);

        // 密钥派生
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey secretKey = keyFactory.generateSecret(keySpec);

        // 返回生成的密钥
        return new SecretKeySpec(secretKey.getEncoded(), "AES");
    }

    /**
     * 生成密钥并返回Base64编码的字符串
     *
     * @param password 口令
     * @return Base64编码的密钥字符串
     * @throws NoSuchAlgorithmException 如果找不到指定的算法
     * @throws InvalidKeySpecException 如果密钥规范无效
     */
    public static String generateKeyAsString(char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeySpec key = generateKey(password);
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    // 私有构造函数，因为这个类只包含静态方法，所以不需要实例
    private PasswordBasedKeyDerivation4() {}
}