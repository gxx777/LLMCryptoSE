import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseOFB4 {

    public static void main(String[] args) throws Exception {
        // 生成AES密钥
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();

        // 加密和发送消息给参与方1
        String message1 = "Hello participant 1!";
        String encryptedMessage1 = encrypt(message1, secretKey);
        System.out.println("Encrypted message for participant 1: " + encryptedMessage1);

        // 加密和发送消息给参与方2
        String message2 = "Hello participant 2!";
        String encryptedMessage2 = encrypt(message2, secretKey);
        System.out.println("Encrypted message for participant 2: " + encryptedMessage2);

        // 加密和发送消息给参与方3
        String message3 = "Hello participant 3!";
        String encryptedMessage3 = encrypt(message3, secretKey);
        System.out.println("Encrypted message for participant 3: " + encryptedMessage3);
    }

    public static String encrypt(String message, SecretKey secretKey) throws Exception {
        // 创建随机初始化向量
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);

        // 创建AES密码器并设置为OFB模式
        Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // 加密消息
        byte[] encrypted = cipher.doFinal(message.getBytes());

        // 将初始化向量和加密后的消息合并为一个字符串
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

        // 使用Base64进行编码
        return Base64.getEncoder().encodeToString(combined);
    }
}