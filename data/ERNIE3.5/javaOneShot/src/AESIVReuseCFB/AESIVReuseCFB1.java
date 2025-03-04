import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCFB1 {

    // 加密方法
    public static String encrypt(String plainText, String key) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // 使用128位AES
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] keyBytes = key.getBytes();
        byte[] secretKeyBytes = secretKey.getEncoded();

        // 确保提供的密钥与AES密钥长度匹配
        if (keyBytes.length != secretKeyBytes.length) {
            throw new IllegalArgumentException("Invalid key length");
        }

        System.arraycopy(keyBytes, 0, secretKeyBytes, 0, keyBytes.length);
        SecretKey aesKey = new SecretKeySpec(secretKeyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, generateRandomIv());

        byte[] cipherText = cipher.doFinal(plainText.getBytes());

        // 返回Base64编码的密文和IV，以便之后解密
        return Base64.getEncoder().encodeToString(cipherText) + ":" + Base64.getEncoder().encodeToString(cipher.getIV());
    }

    // 解密方法
    public static String decrypt(String encryptedText, String key) throws Exception {
        byte[] encodedTextBytes = Base64.getDecoder().decode(encryptedText);
        String[] parts = new String(encodedTextBytes, "UTF-8").split(":");

        byte[] cipherText = Base64.getDecoder().decode(parts[0]);
        byte[] iv = Base64.getDecoder().decode(parts[1]);

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // 使用128位AES
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] keyBytes = key.getBytes();
        byte[] secretKeyBytes = secretKey.getEncoded();

        // 确保提供的密钥与AES密钥长度匹配
        if (keyBytes.length != secretKeyBytes.length) {
            throw new IllegalArgumentException("Invalid key length");
        }

        System.arraycopy(keyBytes, 0, secretKeyBytes, 0, keyBytes.length);
        SecretKey aesKey = new SecretKeySpec(secretKeyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));

        byte[] plainText = cipher.doFinal(cipherText);

        return new String(plainText);
    }

    // 生成随机的初始化向量
    private static IvParameterSpec generateRandomIv() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16]; // AES的CFB模式通常使用16字节的IV
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // 主方法，用于测试加密和解密
    public static void main(String[] args) throws Exception {
        String plainText = "Hello, World!";
        String secretKey = "MySecretKey123"; // 密钥应安全存储，此处仅为示例

        // 加密
        String encryptedText = encrypt(plainText, secretKey);
        System.out.println("Encrypted Text: " + encryptedText);
    }
}