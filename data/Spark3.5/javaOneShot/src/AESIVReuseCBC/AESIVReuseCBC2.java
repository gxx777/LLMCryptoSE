import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCBC2 {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    public static void main(String[] args) throws Exception {
        // 生成密钥
        SecretKey secretKey = generateKey();

        // 生成初始向量
        IvParameterSpec iv1 = generateIV();
        IvParameterSpec iv2 = generateIV();
        IvParameterSpec iv3 = generateIV();

        // 发送方1加密消息
        String message1 = "Hello, Sender 1!";
        String encryptedMessage1 = encrypt(message1, secretKey, iv1);
        System.out.println("Encrypted message from Sender 1: " + encryptedMessage1);

        // 发送方2加密消息
        String message2 = "Hello, Sender 2!";
        String encryptedMessage2 = encrypt(message2, secretKey, iv2);
        System.out.println("Encrypted message from Sender 2: " + encryptedMessage2);

        // 发送方3加密消息
        String message3 = "Hello, Sender 3!";
        String encryptedMessage3 = encrypt(message3, secretKey, iv3);
        System.out.println("Encrypted message from Sender 3: " + encryptedMessage3);
    }

    private static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private static IvParameterSpec generateIV() {
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