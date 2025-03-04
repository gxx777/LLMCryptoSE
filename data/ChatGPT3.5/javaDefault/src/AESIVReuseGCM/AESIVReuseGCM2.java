import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM2 {

    // 生成16字节的随机IV
    private static byte[] generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // 生成AES密钥
    private static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    // 加密消息
    public static String encryptMessage(String message, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] encrypted = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // 解密消息
    public static String decryptMessage(String encryptedMessage, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decoded = Base64.getDecoder().decode(encryptedMessage);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted);
    }

    public static void main(String[] args) throws Exception {
        SecretKey key1 = generateAESKey();
        SecretKey key2 = generateAESKey();
        SecretKey key3 = generateAESKey();

        // 分别生成三个不同的IV
        byte[] iv1 = generateIV();
        byte[] iv2 = generateIV();
        byte[] iv3 = generateIV();

        // 加密消息并发送
        String message = "Hello, Java!";
        String encryptedMessage1 = encryptMessage(message, key1, iv1);
        String encryptedMessage2 = encryptMessage(message, key2, iv2);
        String encryptedMessage3 = encryptMessage(message, key3, iv3);

        // 接收并解密消息
        String decryptedMessage1 = decryptMessage(encryptedMessage1, key1, iv1);
        String decryptedMessage2 = decryptMessage(encryptedMessage2, key2, iv2);
        String decryptedMessage3 = decryptMessage(encryptedMessage3, key3, iv3);

        System.out.println("Decrypted message 1: " + decryptedMessage1);
        System.out.println("Decrypted message 2: " + decryptedMessage2);
        System.out.println("Decrypted message 3: " + decryptedMessage3);
    }
}