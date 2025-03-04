import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESKeyReuse2 {

    // AES密钥（在实际应用中，这个密钥应该通过安全的方式交换和共享）
    private static final String AES_KEY = "ThisIsASecretKey1234567890";

    // 初始化AES密钥
    private static final SecretKeySpec secretKeySpec = new SecretKeySpec(AES_KEY.getBytes(StandardCharsets.UTF_8), "AES");

    // 加密方法
    public static String encrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 解密方法
    public static String decrypt(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    // 测试方法
    public static void main(String[] args) {
        try {
            // 参与方A的消息
            String messageFromA = "Hello from A";
            String encryptedMessageForB = encrypt(messageFromA);
            System.out.println("Encrypted message for B: " + encryptedMessageForB);

            // 参与方B接收并解密消息
            String decryptedMessageFromA = decrypt(encryptedMessageForB);
            System.out.println("Decrypted message from A: " + decryptedMessageFromA);

            // 参与方B的消息
            String messageFromB = "Hello from B";
            String encryptedMessageForC = encrypt(messageFromB);
            System.out.println("Encrypted message for C: " + encryptedMessageForC);

            // 参与方C接收并解密消息
            String decryptedMessageFromB = decrypt(encryptedMessageForC);
            System.out.println("Decrypted message from B: " + decryptedMessageFromB);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}