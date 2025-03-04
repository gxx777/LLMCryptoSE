import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESKeyReuse1 {

    // 共享的AES密钥
    private static final String SHARED_KEY = "ThisIsASharedSecretKey";

    // 加密方法
    public static String encrypt(String plainText, String key) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // 解密方法
    public static String decrypt(String cipherText, String key) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            // 参与方A发送消息给参与方B
            String messageFromAtoB = "Hello from A to B";
            String encryptedMessageAtoB = encrypt(messageFromAtoB, SHARED_KEY);
            System.out.println("Encrypted message from A to B: " + encryptedMessageAtoB);

            // 参与方B接收并解密消息
            String decryptedMessageAtoB = decrypt(encryptedMessageAtoB, SHARED_KEY);
            System.out.println("Decrypted message from A to B: " + decryptedMessageAtoB);

            // 参与方B发送消息给参与方C
            String messageFromBtoC = "Hello from B to C";
            String encryptedMessageBtoC = encrypt(messageFromBtoC, SHARED_KEY);
            System.out.println("Encrypted message from B to C: " + encryptedMessageBtoC);

            // 参与方C接收并解密消息
            String decryptedMessageBtoC = decrypt(encryptedMessageBtoC, SHARED_KEY);
            System.out.println("Decrypted message from B to C: " + decryptedMessageBtoC);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}