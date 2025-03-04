import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class AESKeyReuse3 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

    // 模拟方法：生成安全的随机密钥和IV
    public static byte[] generateSecureRandomKeyAndIV(int keyLength) {
        byte[] keyAndIV = new byte[keyLength + 16]; // AES key + CBC IV
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(keyAndIV);
        return keyAndIV;
    }

    // 加密方法
    public static String encrypt(String message, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // 解密方法
    public static String decrypt(String encryptedMessage, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    // 发送消息给参与方1
    public static String sendMessageToParty1(String message) throws Exception {
        byte[] keyAndIV = generateSecureRandomKeyAndIV(32); // 256-bit key + 128-bit IV
        byte[] key = Arrays.copyOfRange(keyAndIV, 0, 16);
        byte[] iv = Arrays.copyOfRange(keyAndIV, 16, 32);

        String encryptedMessage = encrypt(message, key, iv);
        // 存储或发送密钥和IV给参与方1（实际应用中应安全传输）
        return encryptedMessage;
    }

    // 发送消息给参与方2
    public static String sendMessageToParty2(String message) throws Exception {
        byte[] keyAndIV = generateSecureRandomKeyAndIV(32); // 256-bit key + 128-bit IV
        byte[] key = Arrays.copyOfRange(keyAndIV, 0, 16);
        byte[] iv = Arrays.copyOfRange(keyAndIV, 16, 32);

        String encryptedMessage = encrypt(message, key, iv);
        // 存储或发送密钥和IV给参与方2（实际应用中应安全传输）
        return encryptedMessage;
    }

    // 发送消息给参与方3
    public static String sendMessageToParty3(String message) throws Exception {
        byte[] keyAndIV = generateSecureRandomKeyAndIV(32); // 256-bit key + 128-bit IV
        byte[] key = Arrays.copyOfRange(keyAndIV, 0, 16);
        byte[] iv = Arrays.copyOfRange(keyAndIV, 16, 32);

        String encryptedMessage = encrypt(message, key, iv);
        return encryptedMessage;
    }
}