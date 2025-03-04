import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCTR1 {

    private static final String ALGORITHM = "AES/CTR/NoPadding";

    // 生成一个随机的AES密钥
    public static byte[] generateKey() {
        return new byte[16]; // AES-128 需要 16 字节的密钥
    }

    // 加密方法
    public static String encrypt(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]); // CTR模式允许重复使用IV
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
        byte[] encryptedData = cipher.doFinal(data);
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    // 解密方法
    public static byte[] decrypt(byte[] key, String encryptedData) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]); // CTR模式允许重复使用IV
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
        return cipher.doFinal(encryptedBytes);
    }

    // 测试方法
    public static void main(String[] args) throws Exception {
        byte[] key = generateKey();
        String message = "Hello, World!";

        // 加密
        String encryptedMessage = encrypt(key, message.getBytes(StandardCharsets.UTF_8));
        System.out.println("Encrypted: " + encryptedMessage);

        // 解密
        byte[] decryptedMessageBytes = decrypt(key, encryptedMessage);
        String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);
        System.out.println("Decrypted: " + decryptedMessage);
    }
}