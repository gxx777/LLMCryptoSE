import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCBC2 {

    // 生成AES密钥
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    // 加密数据
    public static String encrypt(String data, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    // 解密数据
    public static String decrypt(String encryptedData, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedData);
    }

    public static void main(String[] args) throws Exception {
        // 生成三个参与方的密钥
        SecretKey key1 = generateAESKey();
        SecretKey key2 = generateAESKey();
        SecretKey key3 = generateAESKey();

        // 设置三个不同的初始向量
        byte[] ivBytes1 = new byte[16];
        new SecureRandom().nextBytes(ivBytes1);
        IvParameterSpec iv1 = new IvParameterSpec(ivBytes1);

        byte[] ivBytes2 = new byte[16];
        new SecureRandom().nextBytes(ivBytes2);
        IvParameterSpec iv2 = new IvParameterSpec(ivBytes2);

        byte[] ivBytes3 = new byte[16];
        new SecureRandom().nextBytes(ivBytes3);
        IvParameterSpec iv3 = new IvParameterSpec(ivBytes3);

        // 加密并发送消息
        String message = "Hello, world!";
        String encryptedMessage1 = encrypt(message, key1, iv1);
        String encryptedMessage2 = encrypt(message, key2, iv2);
        String encryptedMessage3 = encrypt(message, key3, iv3);

        // 解密消息
        String decryptedMessage1 = decrypt(encryptedMessage1, key1, iv1);
        String decryptedMessage2 = decrypt(encryptedMessage2, key2, iv2);
        String decryptedMessage3 = decrypt(encryptedMessage3, key3, iv3);

        // 输出解密后的消息
        System.out.println("Decrypted Message 1: " + decryptedMessage1);
        System.out.println("Decrypted Message 2: " + decryptedMessage2);
        System.out.println("Decrypted Message 3: " + decryptedMessage3);
    }
}