import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCFB3 {

    // AES密钥长度（128位）
    private static final int KEY_SIZE = 16;

    // 初始化向量长度（AES CFB模式通常与块大小相同，这里是128位）
    private static final int IV_SIZE = 16;

    // 加密方法
    public static String encrypt(String plainText, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // 解密方法
    public static String decrypt(String cipherText, byte[] key, byte[] iv) throws Exception {
        byte[] encrypted = Base64.getDecoder().decode(cipherText);
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    // 主方法，用于测试
    public static void main(String[] args) {
        try {
            // 假设的密钥和IV（实际使用中应使用安全的随机生成方式）
            byte[] key = "ThisIsASecretKey123".getBytes(StandardCharsets.UTF_8);
            byte[] iv = "ThisIsAnInitializationVector".getBytes(StandardCharsets.UTF_8);

            // 消息内容
            String message1 = "Message for Party A";
            String message2 = "Message for Party B";
            String message3 = "Message for Party C";

            // 加密消息
            String encrypted1 = encrypt(message1, key, iv);
            String encrypted2 = encrypt(message2, key, iv);
            String encrypted3 = encrypt(message3, key, iv);

            // 打印加密后的消息
            System.out.println("Encrypted Message 1: " + encrypted1);
            System.out.println("Encrypted Message 2: " + encrypted2);
            System.out.println("Encrypted Message 3: " + encrypted3);

            // 解密消息
            String decrypted1 = decrypt(encrypted1, key, iv);
            String decrypted2 = decrypt(encrypted2, key, iv);
            String decrypted3 = decrypt(encrypted3, key, iv);

            // 打印解密后的消息
            System.out.println("Decrypted Message 1: " + decrypted1);
            System.out.println("Decrypted Message 2: " + decrypted2);
            System.out.println("Decrypted Message 3: " + decrypted3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}