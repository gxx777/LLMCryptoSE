import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESKeyReuse4 {
    private static final String ALGORITHM = "AES";
    private static final int KEY_SIZE = 128;

    public static void main(String[] args) throws Exception {
        // 生成密钥
        SecretKey secretKey = generateSecretKey();

        // 三个不同的参与方
        String participant1 = "Alice";
        String participant2 = "Bob";
        String participant3 = "Charlie";

        // 对每个参与方的消息进行加密
        String encryptedMessage1 = encrypt(participant1, secretKey);
        String encryptedMessage2 = encrypt(participant2, secretKey);
        String encryptedMessage3 = encrypt(participant3, secretKey);

        // 输出加密后的消息
        System.out.println("Encrypted message for " + participant1 + ": " + encryptedMessage1);
        System.out.println("Encrypted message for " + participant2 + ": " + encryptedMessage2);
        System.out.println("Encrypted message for " + participant3 + ": " + encryptedMessage3);

        // 对每个参与方的消息进行解密
        String decryptedMessage1 = decrypt(encryptedMessage1, secretKey);
        String decryptedMessage2 = decrypt(encryptedMessage2, secretKey);
        String decryptedMessage3 = decrypt(encryptedMessage3, secretKey);

        // 输出解密后的消息
        System.out.println("Decrypted message for " + participant1 + ": " + decryptedMessage1);
        System.out.println("Decrypted message for " + participant2 + ": " + decryptedMessage2);
        System.out.println("Decrypted message for " + participant3 + ": " + decryptedMessage3);
    }

    private static SecretKey generateSecretKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    private static String encrypt(String message, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String encryptedMessage, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}