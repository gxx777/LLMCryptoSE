import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseOFB3 {

    // AES密钥长度（128位）
    private static final int AES_KEY_SIZE = 16;

    // 生成随机的AES密钥
    private byte[] generateKey() {
        byte[] key = new byte[AES_KEY_SIZE];
        new SecureRandom().nextBytes(key);
        return key;
    }

    // 生成随机的初始化向量（IV）
    private byte[] generateIV() {
        // OFB模式需要的IV长度与块大小相同，对于AES来说是16字节
        byte[] iv = new byte[AES_KEY_SIZE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // 使用AES的OFB模式进行加密
    public String encrypt(String plaintext, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // 使用AES的OFB模式进行解密
    public String decrypt(String encryptedText, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    // 示例方法：演示如何加密和解密消息
    public void demonstrateEncryptionAndDecryption() throws Exception {
        String message1 = "Hello from Party A";
        String message2 = "Hello from Party B";
        String message3 = "Hello from Party C";

        // 生成唯一的密钥
        byte[] key = generateKey();

        // 对每个消息生成唯一的IV
        byte[] iv1 = generateIV();
        byte[] iv2 = generateIV();
        byte[] iv3 = generateIV();

        // 加密消息
        String encrypted1 = encrypt(message1, key, iv1);
        String encrypted2 = encrypt(message2, key, iv2);
        String encrypted3 = encrypt(message3, key, iv3);

        // 解密消息
        String decrypted1 = decrypt(encrypted1, key, iv1);
        String decrypted2 = decrypt(encrypted2, key, iv2);
        String decrypted3 = decrypt(encrypted3, key, iv3);

        // 输出结果
        System.out.println("Original Message 1: " + message1);
        System.out.println("Encrypted Message 1: " + encrypted1);
        System.out.println("Decrypted Message 1: " + decrypted1);

        System.out.println("Original Message 2: " + message2);
        System.out.println("Encrypted Message 2: " + encrypted2);
        System.out.println("Decrypted Message 2: " + decrypted2);

        System.out.println("Original Message 3: " + message3);
        System.out.println("Encrypted Message 3: " + encrypted3);
        System.out.println("Decrypted Message 3: " + decrypted3);
    }

    public static void main(String[] args) throws Exception {
        AESIVReuseOFB3 aes = new AESIVReuseOFB3();
        aes.demonstrateEncryptionAndDecryption();
    }
}