import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESKeyReuse3 {

    public static void main(String[] args) throws Exception {
        // 生成三个不同的密钥
        SecretKey key1 = generateKey();
        SecretKey key2 = generateKey();
        SecretKey key3 = generateKey();

        // 发送方1使用key1加密消息
        String message1 = "Hello, Parties 2 and 3!";
        String encryptedMessage1 = encrypt(message1, key1);
        System.out.println("Encrypted message for Party 2 and 3: " + encryptedMessage1);

        // 发送方2使用key2加密消息
        String message2 = "Hello, Party 3!";
        String encryptedMessage2 = encrypt(message2, key2);
        System.out.println("Encrypted message for Party 3: " + encryptedMessage2);

        // 发送方3使用key3加密消息
        String message3 = "Hello, Parties 1 and 2!";
        String encryptedMessage3 = encrypt(message3, key3);
        System.out.println("Encrypted message for Party 1 and 2: " + encryptedMessage3);
    }

    private static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private static String encrypt(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}