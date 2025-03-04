import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;

public class AESIVReuseCBC4 {

    private static final String KEY = "ThisIsASecretKey"; // 实际开发中请使用安全的密钥生成方法
    private static final byte[] IV = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; // 重复使用的初始化向量

    // 加密方法
    public static String encrypt(String valueToEncrypt) throws Exception {
        Key key = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV));
        byte[] encryptedValue = cipher.doFinal(valueToEncrypt.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedValue);
    }

    // 解密方法
    public static String decrypt(String encryptedValue) throws Exception {
        Key key = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));
        byte[] originalValue = cipher.doFinal(Base64.getDecoder().decode(encryptedValue));
        return new String(originalValue, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            // 示例用法
            String message1 = "Hello, World!";
            String message2 = "Another secret message";
            String message3 = "This is the third one";

            String encrypted1 = encrypt(message1);
            String encrypted2 = encrypt(message2);
            String encrypted3 = encrypt(message3);

            System.out.println("Encrypted Message 1: " + encrypted1);
            System.out.println("Encrypted Message 2: " + encrypted2);
            System.out.println("Encrypted Message 3: " + encrypted3);

            String decrypted1 = decrypt(encrypted1);
            String decrypted2 = decrypt(encrypted2);
            String decrypted3 = decrypt(encrypted3);

            System.out.println("Decrypted Message 1: " + decrypted1);
            System.out.println("Decrypted Message 2: " + decrypted2);
            System.out.println("Decrypted Message 3: " + decrypted3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}