import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionGCM4 {

    // 加密用的AES密钥长度，必须是128位的倍数，且最大支持256位
    private static final int KEY_SIZE = 256;

    // GCM模式的tag长度，通常为128位
    private static final int TAG_SIZE = 128;

    // 生成AES密钥
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    // 加密数据
    public static String encrypt(String data, SecretKey key) throws Exception {
        byte[] utf8Data = data.getBytes(StandardCharsets.UTF_8);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_SIZE, new SecureRandom().generateSeed(12));

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);

        byte[] encryptedData = cipher.doFinal(utf8Data);

        // 将加密数据和tag拼接后返回
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    // 解密数据
    public static String decrypt(String encryptedData, SecretKey key) throws Exception {
        byte[] dataBytes = Base64.getDecoder().decode(encryptedData);

        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_SIZE, dataBytes, 0, 12);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);

        byte[] decryptedData = cipher.doFinal(dataBytes, 12, dataBytes.length - 12);

        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        // 生成密钥
        SecretKey key = generateKey();

        // 加密数据
        String originalData = "Hello, World!";
        String encryptedData = encrypt(originalData, key);
        System.out.println("Encrypted: " + encryptedData);

        // 解密数据
        String decryptedData = decrypt(encryptedData, key);
        System.out.println("Decrypted: " + decryptedData);
    }
}