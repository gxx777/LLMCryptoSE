import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESKeyReuse2 {

    private static final String ALGORITHM = "AES";

    // 生成新的AES密钥
    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(128); // 可以使用128, 192, 或 256位密钥
        return keyGenerator.generateKey();
    }

    // 加密消息
    public static String encrypt(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 解密消息
    public static String decrypt(String encryptedMessage, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            // 生成密钥
            SecretKey key = generateKey();

            // 假设有三个参与方
            String message1 = "Message for Participant 1";
            String message2 = "Message for Participant 2";
            String message3 = "Message for Participant 3";

            // 加密消息
            String encryptedMessage1 = encrypt(message1, key);
            String encryptedMessage2 = encrypt(message2, key);
            String encryptedMessage3 = encrypt(message3, key);

            System.out.println("Encrypted Message 1: " + encryptedMessage1);
            System.out.println("Encrypted Message 2: " + encryptedMessage2);
            System.out.println("Encrypted Message 3: " + encryptedMessage3);

            // 解密消息
            String decryptedMessage1 = decrypt(encryptedMessage1, key);
            String decryptedMessage2 = decrypt(encryptedMessage2, key);
            String decryptedMessage3 = decrypt(encryptedMessage3, key);

            System.out.println("Decrypted Message 1: " + decryptedMessage1);
            System.out.println("Decrypted Message 2: " + decryptedMessage2);
            System.out.println("Decrypted Message 3: " + decryptedMessage3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}