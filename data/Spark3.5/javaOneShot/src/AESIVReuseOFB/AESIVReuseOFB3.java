import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseOFB3 {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/OFB/PKCS5Padding";
    private static final int KEY_SIZE = 128;

    public static void main(String[] args) throws Exception {
        // 生成随机的AES密钥和初始向量（IV）
        SecretKey secretKey = generateRandomKey();
        IvParameterSpec iv = generateRandomIV();

        // 使用AES OFB模式加密消息
        String message1 = "Hello, Party 1!";
        String message2 = "Hello, Party 2!";
        String message3 = "Hello, Party 3!";

        String encryptedMessage1 = encrypt(message1, secretKey, iv);
        String encryptedMessage2 = encrypt(message2, secretKey, iv);
        String encryptedMessage3 = encrypt(message3, secretKey, iv);

        // 将加密后的消息发送给三个不同的参与方
        sendMessageToParty1(encryptedMessage1);
        sendMessageToParty2(encryptedMessage2);
        sendMessageToParty3(encryptedMessage3);
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

    private static void sendMessageToParty1(String encryptedMessage) {
        System.out.println("Sending encrypted message to Party 1: " + encryptedMessage);
    }

    private static void sendMessageToParty2(String encryptedMessage) {
        System.out.println("Sending encrypted message to Party 2: " + encryptedMessage);
    }

    private static void sendMessageToParty3(String encryptedMessage) {
        System.out.println("Sending encrypted message to Party 3: " + encryptedMessage);
    }
}