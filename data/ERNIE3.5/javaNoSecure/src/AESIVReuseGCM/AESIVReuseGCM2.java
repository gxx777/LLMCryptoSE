import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM2 {

    private static final int TAG_LENGTH = 128; // GCM的认证标签长度
    private static final int KEY_SIZE = 256; // AES密钥大小
    private static final SecureRandom random = new SecureRandom();

    // 生成AES密钥
    private static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    // 加密方法
    public static String encrypt(String plaintext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    // 解密方法
    public static String decrypt(String ciphertext, SecretKey key, byte[] iv) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(ciphertext);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        return new String(cipher.doFinal(bytes), StandardCharsets.UTF_8);
    }

    // 主方法，用于演示
    public static void main(String[] args) throws Exception {
        // 生成AES密钥
        SecretKey key = generateKey();

        // 初始化向量IV（实际使用中，每次加密都应该使用新的随机IV）
        byte[] iv = new byte[12]; // AES-GCM的IV长度通常为12字节
        random.nextBytes(iv);

        // 参与方1发送的消息
        String message1 = "Hello from Party 1!";
        String encryptedMessage1 = encrypt(message1, key, iv);
        System.out.println("Encrypted message 1: " + encryptedMessage1);

        // 参与方2发送消息
        String message2 = "Hello from Party 2!";
        String encryptedMessage2 = encrypt(message2, key, iv); // 注意：这里重用了IV
        System.out.println("Encrypted message 2: " + encryptedMessage2);

        // 参与方3发送消息
        String message3 = "Hello from Party 3!";
        String encryptedMessage3 = encrypt(message3, key, iv); // 注意：这里重用了IV
        System.out.println("Encrypted message 3: " + encryptedMessage3);

        // 解密消息（为了演示，我们假设接收方知道正确的密钥和IV）
        System.out.println("Decrypted message 1: " + decrypt(encryptedMessage1, key, iv));
        System.out.println("Decrypted message 2: " + decrypt(encryptedMessage2, key, iv));
        System.out.println("Decrypted message 3: " + decrypt(encryptedMessage3, key, iv));
    }
}