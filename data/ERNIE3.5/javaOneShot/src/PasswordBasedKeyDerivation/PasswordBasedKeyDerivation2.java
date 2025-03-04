import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class PasswordBasedKeyDerivation2 {

    private static final int ITERATIONS = 65536; // PBKDF2迭代次数
    private static final int KEY_LENGTH = 256; // 密钥长度，以位为单位

    /**
     * 使用PBKDF2和HMAC-SHA256从密码派生出密钥。
     *
     * @param password  用户密码
     * @param salt      随机盐值
     * @return          派生出的密钥
     * @throws NoSuchAlgorithmException   如果PBKDF2或HMAC-SHA256不可用
     * @throws InvalidKeySpecException     如果密钥规范无效
     */
    public static SecretKey deriveKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec keySpec = factory.getKeySpec(factory.generateSecret(spec), SecretKeySpec.class);
        return (SecretKey) keySpec;
    }

    /**
     * 示例：从密码派生出密钥并打印其十六进制表示。
     *
     * @param args 命令行参数
     * @throws NoSuchAlgorithmException   如果PBKDF2或HMAC-SHA256不可用
     * @throws InvalidKeySpecException     如果密钥规范无效
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String password = "mySecurePassword";
        byte[] salt = new byte[16]; // 盐应该是随机的，这里仅作为示例
        java.util.Arrays.fill(salt, (byte) 0x95); // 用某个固定值填充盐，实际中应使用随机值

        SecretKey key = deriveKey(password.toCharArray(), salt);
        System.out.println("Derived Key (hex): " + bytesToHex(key.getEncoded()));
    }

    /**
     * 将字节数组转换为十六进制字符串。
     *
     * @param bytes 要转换的字节数组
     * @return      转换后的十六进制字符串
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}