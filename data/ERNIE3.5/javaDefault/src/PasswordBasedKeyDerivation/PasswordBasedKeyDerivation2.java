import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class PasswordBasedKeyDerivation2 {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA512";
    private static final int ITERATIONS = 65536; // 推荐值
    private static final int KEY_LENGTH = 256; // 输出密钥长度，以位为单位

    public static byte[] deriveKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        return keyFactory.generateSecret(keySpec).getEncoded();
    }

    public static String deriveKeyAsBase64(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return Base64.getEncoder().encodeToString(deriveKey(password, salt));
    }

    public static void main(String[] args) {
        try {
            // 随机生成盐值
            byte[] salt = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(salt);

            // 派生密钥
            String password = "mySecurePassword";
            byte[] key = deriveKey(password, salt);

            // 将密钥转换为Base64编码的字符串
            String base64Key = new String(Base64.getEncoder().encode(key));

            // 打印结果
            System.out.println("Derived Key (Base64): " + base64Key);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }
}