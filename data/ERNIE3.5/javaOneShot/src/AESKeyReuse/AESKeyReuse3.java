import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESKeyReuse3 {

    // AES密钥长度，可以是128, 192, 或 256位
    private static final int AES_KEY_SIZE = 256;

    // 生成AES密钥
    private static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(AES_KEY_SIZE);
        return keyGenerator.generateKey();
    }

    // 加密方法
    public static String encrypt(String plainText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 解密方法
    public static String decrypt(String encryptedText, SecretKey secretKey) throws Exception {
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    // 主方法，演示如何使用
    public static void main(String[] args) throws Exception {
        // 假设有三个参与方A, B, C
        String messageA = "Hello from A";
        String messageB = "Hello from B";
        String messageC = "Hello from C";

        // 为每个参与方生成一个独立的AES密钥
        SecretKey secretKeyA = generateKey();
        SecretKey secretKeyB = generateKey();
        SecretKey secretKeyC = generateKey();

        // 加密消息
        String encryptedMessageA = encrypt(messageA, secretKeyA);
        String encryptedMessageB = encrypt(messageB, secretKeyB);
        String encryptedMessageC = encrypt(messageC, secretKeyC);

        // 假设接收方B收到A的消息，并使用自己的密钥解密，这将失败，因为密钥不匹配
        try {
            String decryptedMessage = decrypt(encryptedMessageA, secretKeyB);
            System.out.println("Decrypted message from A: " + decryptedMessage);
        } catch (Exception e) {
            System.out.println("Decryption failed for message from A using B's key.");
        }

        // 正确的解密方式：使用发送方的密钥解密
        String decryptedMessageA = decrypt(encryptedMessageA, secretKeyA);
        System.out.println("Decrypted message from A: " + decryptedMessageA);

        // 同理，其他消息也应使用相应的密钥解密
        String decryptedMessageB = decrypt(encryptedMessageB, secretKeyB);
        System.out.println("Decrypted message from B: " + decryptedMessageB);

        String decryptedMessageC = decrypt(encryptedMessageC, secretKeyC);
        System.out.println("Decrypted message from C: " + decryptedMessageC);
    }
}