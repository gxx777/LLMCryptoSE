import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESIVReuseCBC3 {
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 128;

    public static void main(String[] args) throws Exception {
        // 生成AES密钥
        SecretKey secretKey = generateAESKey();

        // 初始化向量
        byte[] iv = new byte[16];
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // 创建加密器
        Cipher encryptCipher = Cipher.getInstance(ALGORITHM);
        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        // 创建解密器
        Cipher decryptCipher = Cipher.getInstance(ALGORITHM);
        decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        // 三个参与方的消息
        String message1 = "Message from participant 1";
        String message2 = "Message from participant 2";
        String message3 = "Message from participant 3";

        // 加密并发送消息
        String encryptedMessage1 = encryptAndSend(encryptCipher, message1);
        String encryptedMessage2 = encryptAndSend(encryptCipher, message2);
        String encryptedMessage3 = encryptAndSend(encryptCipher, message3);

        // 接收并解密消息
        String decryptedMessage1 = receiveAndDecrypt(decryptCipher, encryptedMessage1);
        String decryptedMessage2 = receiveAndDecrypt(decryptCipher, encryptedMessage2);
        String decryptedMessage3 = receiveAndDecrypt(decryptCipher, encryptedMessage3);

        // 输出解密后的消息
        System.out.println("Decrypted message from participant 1: " + decryptedMessage1);
        System.out.println("Decrypted message from participant 2: " + decryptedMessage2);
        System.out.println("Decrypted message from participant 3: " + decryptedMessage3);
    }

    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    private static String encryptAndSend(Cipher cipher, String message) throws Exception {
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String receiveAndDecrypt(Cipher cipher, String encryptedMessage) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}