import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCFB3 {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CFB8/NoPadding";
    private static final int KEY_SIZE = 128;

    public static void main(String[] args) throws Exception {
        // 生成随机的AES密钥和初始向量（IV）
        SecretKey secretKey = generateRandomKey();
        IvParameterSpec iv = generateRandomIV();

        // 使用AES的CFB模式对三个不同参与方分别发送消息
        String message1 = "Hello, Parties 1!";
        String message2 = "Hello, Parties 2!";
        String message3 = "Hello, Parties 3!";

        String encryptedMessage1 = encrypt(message1, secretKey, iv);
        String encryptedMessage2 = encrypt(message2, secretKey, iv);
        String encryptedMessage3 = encrypt(message3, secretKey, iv);

        System.out.println("Encrypted Message 1: " + encryptedMessage1);
        System.out.println("Encrypted Message 2: " + encryptedMessage2);
        System.out.println("Encrypted Message 3: " + encryptedMessage3);
    }

    private static SecretKey generateRandomKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    private static IvParameterSpec generateRandomIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private static String encrypt(String message, SecretKey secretKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}