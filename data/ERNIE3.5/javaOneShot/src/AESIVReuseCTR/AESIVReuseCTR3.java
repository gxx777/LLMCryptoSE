import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR3 {

    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final int KEY_SIZE = 128; // 可以选择128, 192, 256位密钥

    // 生成AES密钥
    private static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    // 加密方法
    public static String encrypt(String plainText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, generateIv());
        byte[] cipherText = cipher.doFinal(plainText.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(cipherText);
    }

    // 解密方法
    public static String decrypt(String cipherText, SecretKey key) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, generateIv());
        return new String(cipher.doFinal(bytes), "UTF-8");
    }

    // 生成随机的初始化向量（IV）
    private static IvParameterSpec generateIv() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16]; // AES CTR模式要求IV长度为16字节
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // 主方法，用于演示
    public static void main(String[] args) throws Exception {
        // 生成密钥
        SecretKey key = generateKey();

        // 第一个参与方发送的消息
        String message1 = "Hello from Party 1";
        String encryptedMessage1 = encrypt(message1, key);
        System.out.println("Encrypted message 1: " + encryptedMessage1);

        // 第二个参与方发送消息
        String message2 = "Hello from Party 2";
        String encryptedMessage2 = encrypt(message2, key);
        System.out.println("Encrypted message 2: " + encryptedMessage2);

        // 第三个参与方发送消息
        String message3 = "Hello from Party 3";
        String encryptedMessage3 = encrypt(message3, key);
        System.out.println("Encrypted message 3: " + encryptedMessage3);

        // 解密消息
        System.out.println("Decrypted message 1: " + decrypt(encryptedMessage1, key));
        System.out.println("Decrypted message 2: " + decrypt(encryptedMessage2, key));
        System.out.println("Decrypted message 3: " + decrypt(encryptedMessage3, key));
    }
}