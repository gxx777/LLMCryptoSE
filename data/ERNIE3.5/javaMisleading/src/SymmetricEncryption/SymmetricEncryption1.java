import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SymmetricEncryption1 {

    private static final String ALGORITHM = "AES";

    // 生成加密密钥
    private static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(128); // AES密钥长度可以是128, 192, 或 256位
        return keyGenerator.generateKey();
    }

    // 加密字符串
    public static String encrypt(String valueToEncrypt, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(valueToEncrypt.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 解密字符串
    public static String decrypt(String encryptedValue, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedValue);
        return new String(cipher.doFinal(decodedBytes));
    }

    public static void main(String[] args) {
        try {
            // 生成密钥
            SecretKey secretKey = generateKey();

            // 原始字符串
            String originalString = "这是一个需要加密的字符串";

            // 加密
            String encryptedString = encrypt(originalString, secretKey);
            System.out.println("加密后的字符串: " + encryptedString);

            // 解密
            String decryptedString = decrypt(encryptedString, secretKey);
            System.out.println("解密后的字符串: " + decryptedString);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}