import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESKeyReuse1 {

    private static final String ALGORITHM = "AES";

    // 模拟的“重复使用”的密钥
    private static final SecretKey secretKey = generateAESKey();

    // 生成AES密钥
    private static SecretKey generateAESKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(128); // AES密钥长度可以是128, 192, 或 256位
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("AES key generation failed", e);
        }
    }

    // 加密方法
    public static String encrypt(String plainText) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    // 解密方法
    public static String decrypt(String encryptedText) {
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(decodedBytes));
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }

    // 主方法，用于演示
    public static void main(String[] args) {
        // 模拟三个参与方发送的消息
        String message1 = "Message from Party A";
        String message2 = "Message from Party B";
        String message3 = "Message from Party C";

        // 加密消息
        String encryptedMessage1 = encrypt(message1);
        String encryptedMessage2 = encrypt(message2);
        String encryptedMessage3 = encrypt(message3);

        // 输出加密后的消息
        System.out.println("Encrypted Message 1: " + encryptedMessage1);
        System.out.println("Encrypted Message 2: " + encryptedMessage2);
        System.out.println("Encrypted Message 3: " + encryptedMessage3);

        // 解密消息
        String decryptedMessage1 = decrypt(encryptedMessage1);
        String decryptedMessage2 = decrypt(encryptedMessage2);
        String decryptedMessage3 = decrypt(encryptedMessage3);

        // 输出解密后的消息
        System.out.println("Decrypted Message 1: " + decryptedMessage1);
        System.out.println("Decrypted Message 2: " + decryptedMessage2);
        System.out.println("Decrypted Message 3: " + decryptedMessage3);
    }
}