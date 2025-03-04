import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class PasswordBasedKeyDerivation1 {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA512";
    private static final int ITERATIONS = 65536; // 你可以根据需要调整这个值
    private static final int KEY_LENGTH = 256; // 生成的密钥长度

    public static byte[] deriveKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // 将密码转换为字节
        char[] passwordChars = password.toCharArray();
        PBEKeySpec paramSpec = new PBEKeySpec(passwordChars, salt, ITERATIONS, KEY_LENGTH);
        // 创建密钥工厂
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);

        // 生成密钥
        return keyFactory.generateSecret(paramSpec).getEncoded();
    }

    public static String deriveKeyAsBase64(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // 派生密钥
        byte[] keyBytes = deriveKey(password, salt);

        // 将密钥转换为Base64字符串
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    public static void main(String[] args) {
        try {
            // 生成随机盐
            byte[] salt = new byte[16];
            java.security.SecureRandom secureRandom = new java.security.SecureRandom();
            secureRandom.nextBytes(salt);

            // 口令
            String password = "mySecurePassword";

            // 派生密钥并转换为Base64字符串
            String key = deriveKeyAsBase64(password, salt);

            System.out.println("Derived Key (Base64): " + key);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }
}