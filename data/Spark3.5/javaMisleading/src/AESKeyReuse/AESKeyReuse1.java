import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESKeyReuse1 {

    public static void main(String[] args) throws Exception {
        // 生成一个AES密钥
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();

        // 创建三个不同的消息
        String message1 = "Hello, Parties 1!";
        String message2 = "Hello, Parties 2!";
        String message3 = "Hello, Parties 3!";

        // 使用相同的密钥对三个消息进行加密
        String encryptedMessage1 = encrypt(message1, secretKey);
        String encryptedMessage2 = encrypt(message2, secretKey);
        String encryptedMessage3 = encrypt(message3, secretKey);

        System.out.println("Encrypted Message 1: " + encryptedMessage1);
        System.out.println("Encrypted Message 2: " + encryptedMessage2);
        System.out.println("Encrypted Message 3: " + encryptedMessage3);

        // 使用相同的密钥对三个加密后的消息进行解密
        String decryptedMessage1 = decrypt(encryptedMessage1, secretKey);
        String decryptedMessage2 = decrypt(encryptedMessage2, secretKey);
        String decryptedMessage3 = decrypt(encryptedMessage3, secretKey);

        System.out.println("Decrypted Message 1: " + decryptedMessage1);
        System.out.println("Decrypted Message 2: " + decryptedMessage2);
        System.out.println("Decrypted Message 3: " + decryptedMessage3);
    }

    private static String encrypt(String message, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String encryptedMessage, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}