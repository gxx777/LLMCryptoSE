import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESKeyReuse4 {

    // 加密方法
    public static String encrypt(String plainText, String key) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey secretKey = keyGenerator.generateKey();

        // 这里不应该直接使用传入的key，而是应该生成一个新的密钥
        // 如果需要重复使用相同的密钥加密多个消息，应该使用某种密钥派生函数，如PBKDF2、HMAC等

        byte[] encodedKey = secretKey.getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(encodedKey, "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        byte[] cipherText = cipher.doFinal(plainText.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(cipherText);
    }

    // 解密方法
    public static String decrypt(String cipherText, String key) throws Exception {
        // 同上，这里也不应该直接使用传入的key

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] encodedKey = secretKey.getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(encodedKey, "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText, "UTF-8");
    }

    public static void main(String[] args) {
        try {
            // 示例：加密
            String originalText = "Hello, World!";
            String encryptionKey = "myEncryptionKey"; // 实际应用中，这个密钥不应该硬编码
            String encryptedText = encrypt(originalText, encryptionKey);
            System.out.println("Encrypted Text: " + encryptedText);

            // 示例：解密
            String decryptedText = decrypt(encryptedText, encryptionKey);
            System.out.println("Decrypted Text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}