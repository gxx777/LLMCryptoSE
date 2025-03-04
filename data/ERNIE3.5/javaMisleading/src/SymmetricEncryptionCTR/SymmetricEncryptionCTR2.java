import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

public class SymmetricEncryptionCTR2 {

    private static final String ALGORITHM = "AES/CTR/NoPadding";

    // 加密方法
    public static byte[] encrypt(String plainText, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]); // CTR模式不需要初始化向量，但API需要它
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
        
        return cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    }

    // 解密方法
    public static byte[] decrypt(byte[] cipherText, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]); // 同上
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
        
        return cipher.doFinal(cipherText);
    }

    // 生成安全的随机密钥
    public static byte[] generateKey(int keySize) throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[keySize];
        secureRandom.nextBytes(key);
        return key;
    }

    // 主方法，用于测试
    public static void main(String[] args) throws Exception {
        // 生成安全的密钥
        byte[] key = generateKey(16); // AES-128需要16字节的密钥

        // 原始字符串
        String originalText = "This is a secret message!";

        // 加密
        byte[] encryptedText = encrypt(originalText, key);
        System.out.println("Encrypted Text: " + Arrays.toString(encryptedText));

        // 解密
        byte[] decryptedText = decrypt(encryptedText, key);
        System.out.println("Decrypted Text: " + new String(decryptedText, StandardCharsets.UTF_8));
    }
}