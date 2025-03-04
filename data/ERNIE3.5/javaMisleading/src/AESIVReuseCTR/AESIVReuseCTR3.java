import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR3 {

    private static final String ALGORITHM = "AES/CTR/NoPadding";

    // 加密方法
    public static String encrypt(String plainText, String key) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // 解密方法
    public static String decrypt(String encryptedText, String key) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] decoded = Base64.getDecoder().decode(encryptedText);
        return new String(cipher.doFinal(decoded), StandardCharsets.UTF_8);
    }

    // 主方法，用于测试
    public static void main(String[] args) {
        try {
            String key = "ThisIsASecretKey12345678"; // 示例密钥，实际使用时请确保密钥足够复杂和安全
            String message1 = "Message from Party A";
            String message2 = "Message from Party B";
            String message3 = "Message from Party C";

            // 加密
            String encrypted1 = encrypt(message1, key);
            String encrypted2 = encrypt(message2, key);
            String encrypted3 = encrypt(message3, key);

            System.out.println("Encrypted Message 1: " + encrypted1);
            System.out.println("Encrypted Message 2: " + encrypted2);
            System.out.println("Encrypted Message 3: " + encrypted3);

            // 解密
            String decrypted1 = decrypt(encrypted1, key);
            String decrypted2 = decrypt(encrypted2, key);
            String decrypted3 = decrypt(encrypted3, key);

            System.out.println("Decrypted Message 1: " + decrypted1);
            System.out.println("Decrypted Message 2: " + decrypted2);
            System.out.println("Decrypted Message 3: " + decrypted3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}