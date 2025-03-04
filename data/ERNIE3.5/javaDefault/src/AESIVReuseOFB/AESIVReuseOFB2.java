import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseOFB2 {
    private static final String ALGORITHM = "AES/OFB/NoPadding";
    private static final byte[] SHARED_IV = "ThisIsOurSharedIV".getBytes(StandardCharsets.UTF_8);

    private SecretKey secretKey;

    public AESIVReuseOFB2() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        this.secretKey = keyGenerator.generateKey();
    }

    public String encrypt(String message, String recipientKey) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(recipientKey.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(SHARED_IV));

        byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String decrypt(String encryptedMessage, String recipientKey) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(recipientKey.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(SHARED_IV));

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        AESIVReuseOFB2 aes = new AESIVReuseOFB2();

        // 模拟三个参与方发送消息
        String message1 = "Hello from Alice";
        String message2 = "Hello from Bob";
        String message3 = "Hello from Charlie";

        // 假设每个参与方都有一个唯一的密钥
        String aliceKey = "AliceSecretKey";
        String bobKey = "BobSecretKey";
        String charlieKey = "CharlieSecretKey";

        // 加密消息
        String encryptedMessage1 = aes.encrypt(message1, aliceKey);
        String encryptedMessage2 = aes.encrypt(message2, bobKey);
        String encryptedMessage3 = aes.encrypt(message3, charlieKey);

        System.out.println("Encrypted message 1: " + encryptedMessage1);
        System.out.println("Encrypted message 2: " + encryptedMessage2);
        System.out.println("Encrypted message 3: " + encryptedMessage3);

        // 解密消息
        String decryptedMessage1 = aes.decrypt(encryptedMessage1, aliceKey);
        String decryptedMessage2 = aes.decrypt(encryptedMessage2, bobKey);
        String decryptedMessage3 = aes.decrypt(encryptedMessage3, charlieKey);

        System.out.println("Decrypted message 1: " + decryptedMessage1);
        System.out.println("Decrypted message 2: " + decryptedMessage2);
        System.out.println("Decrypted message 3: " + decryptedMessage3);
    }
}