import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESKeyReuse4 {

    private static final String ALGORITHM = "AES";

    // 生成新的AES密钥
    public static SecretKey generateNewKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(128); // 可以选择128, 192, 或 256位密钥
        return keyGenerator.generateKey();
    }

    // 使用给定的密钥加密消息
    public static String encrypt(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 使用给定的密钥解密消息
    public static String decrypt(String encryptedMessage, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            // 生成新密钥
            SecretKey key = generateNewKey();

            // 模拟三个参与方发送消息
            String message1 = "Message from Party A";
            String message2 = "Message from Party B";
            String message3 = "Message from Party C";

            // 加密消息
            String encryptedMessage1 = encrypt(message1, key);
            String encryptedMessage2 = encrypt(message2, key);
            String encryptedMessage3 = encrypt(message3, key);

            // 解密消息
            String decryptedMessage1 = decrypt(encryptedMessage1, key);
            String decryptedMessage2 = decrypt(encryptedMessage2, key);
            String decryptedMessage3 = decrypt(encryptedMessage3, key);

            // 输出结果
            System.out.println("Original Message 1: " + message1);
            System.out.println("Encrypted Message 1: " + encryptedMessage1);
            System.out.println("Decrypted Message 1: " + decryptedMessage1);

            System.out.println("Original Message 2: " + message2);
            System.out.println("Encrypted Message 2: " + encryptedMessage2);
            System.out.println("Decrypted Message 2: " + decryptedMessage2);

            System.out.println("Original Message 3: " + message3);
            System.out.println("Encrypted Message 3: " + encryptedMessage3);
            System.out.println("Decrypted Message 3: " + decryptedMessage3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}