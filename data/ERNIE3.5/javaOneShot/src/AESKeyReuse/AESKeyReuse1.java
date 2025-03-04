import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESKeyReuse1 {

    private static final String ALGORITHM = "AES";

    public static void main(String[] args) {
        try {
            // 生成三个不同的AES密钥
            SecretKey key1 = generateAESKey();
            SecretKey key2 = generateAESKey();
            SecretKey key3 = generateAESKey();

            // 原始消息
            String originalMessage = "Hello, this is a secret message!";

            // 使用第一个密钥加密消息
            String encryptedMessage1 = encrypt(originalMessage, key1);
            System.out.println("Encrypted with Key 1: " + encryptedMessage1);

            // 使用第二个密钥解密第一个密钥加密的消息（这是不安全的，因为密钥不应该重用）
            String decryptedMessage1 = decrypt(encryptedMessage1, key2);
            System.out.println("Decrypted with Key 2: " + decryptedMessage1);

            // 使用第三个密钥加密消息
            String encryptedMessage2 = encrypt(originalMessage, key3);
            System.out.println("Encrypted with Key 3: " + encryptedMessage2);

            // 使用第一个密钥解密第三个密钥加密的消息（这同样是不安全的）
            String decryptedMessage2 = decrypt(encryptedMessage2, key1);
            System.out.println("Decrypted with Key 1: " + decryptedMessage2);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(128); // AES-128
        return keyGenerator.generateKey();
    }

    public static String encrypt(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedMessage, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}