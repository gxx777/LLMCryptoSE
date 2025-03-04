import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESKeyReuse3 {

    private static final String ALGORITHM = "AES";

    // 生成AES密钥
    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(128); // 使用128位AES
        return keyGenerator.generateKey();
    }

    // 使用AES加密消息
    public static String encrypt(String plainText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // 使用AES解密消息
    public static String decrypt(String encryptedText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decoded = Base64.getDecoder().decode(encryptedText);
        return new String(cipher.doFinal(decoded));
    }

    public static void main(String[] args) {
        try {
            // 假设三个参与方共享同一个密钥
            SecretKey sharedSecretKey = generateKey();

            // 参与方A发送消息
            String messageA = "Message from Party A";
            String encryptedMessageA = encrypt(messageA, sharedSecretKey);
            System.out.println("Encrypted Message A: " + encryptedMessageA);

            // 参与方B接收并解密消息
            String decryptedMessageA = decrypt(encryptedMessageA, sharedSecretKey);
            System.out.println("Decrypted Message A: " + decryptedMessageA);

            // 参与方B发送消息
            String messageB = "Message from Party B";
            String encryptedMessageB = encrypt(messageB, sharedSecretKey);
            System.out.println("Encrypted Message B: " + encryptedMessageB);

            // 参与方A接收并解密消息
            String decryptedMessageB = decrypt(encryptedMessageB, sharedSecretKey);
            System.out.println("Decrypted Message B: " + decryptedMessageB);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}