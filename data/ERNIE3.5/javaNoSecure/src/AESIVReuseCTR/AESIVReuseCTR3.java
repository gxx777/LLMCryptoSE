import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR3 {

    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final byte[] IV = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

    public static void main(String[] args) throws Exception {
        // 初始化密钥生成器
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128, new SecureRandom());

        // 参与者1
        String message1 = "Message for participant 1";
        SecretKey key1 = keyGenerator.generateKey();
        byte[] encrypted1 = encrypt(message1.getBytes(StandardCharsets.UTF_8), key1, IV);
        System.out.println("Encrypted message 1: " + Base64.getEncoder().encodeToString(encrypted1));

        // 参与者2
        String message2 = "Message for participant 2";
        SecretKey key2 = keyGenerator.generateKey();
        byte[] encrypted2 = encrypt(message2.getBytes(StandardCharsets.UTF_8), key2, IV);
        System.out.println("Encrypted message 2: " + Base64.getEncoder().encodeToString(encrypted2));

        // 参与者3
        String message3 = "Message for participant 3";
        SecretKey key3 = keyGenerator.generateKey();
        byte[] encrypted3 = encrypt(message3.getBytes(StandardCharsets.UTF_8), key3, IV);
        System.out.println("Encrypted message 3: " + Base64.getEncoder().encodeToString(encrypted3));
    }

    private static byte[] encrypt(byte[] data, SecretKey key, byte[] iv) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

        return cipher.doFinal(data);
    }
}