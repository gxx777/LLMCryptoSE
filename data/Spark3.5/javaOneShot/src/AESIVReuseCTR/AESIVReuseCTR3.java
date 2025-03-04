import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class AESIVReuseCTR3 {
    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final int KEY_SIZE = 128;
    private static final int IV_SIZE = 16;

    public static void main(String[] args) throws Exception {
        // 生成密钥
        SecretKey secretKey = generateSecretKey();

        // 生成初始向量
        IvParameterSpec iv = generateIV();

        // 创建三个不同的消息
        String message1 = "Hello, participant 1!";
        String message2 = "Hello, participant 2!";
        String message3 = "Hello, participant 3!";

        // 使用AES CTR模式加密消息
        byte[] encryptedMessage1 = encrypt(message1, secretKey, iv);
        byte[] encryptedMessage2 = encrypt(message2, secretKey, iv);
        byte[] encryptedMessage3 = encrypt(message3, secretKey, iv);

        // 输出加密后的消息
        System.out.println("Encrypted message 1: " + new String(encryptedMessage1));
        System.out.println("Encrypted message 2: " + new String(encryptedMessage2));
        System.out.println("Encrypted message 3: " + new String(encryptedMessage3));
    }

    private static SecretKey generateSecretKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    private static IvParameterSpec generateIV() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private static byte[] encrypt(String message, SecretKey secretKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        return cipher.doFinal(message.getBytes());
    }
}