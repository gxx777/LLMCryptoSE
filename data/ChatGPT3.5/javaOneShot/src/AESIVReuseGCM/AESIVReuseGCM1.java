import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM1 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128;

    public static void main(String[] args) throws Exception {
        // 生成随机密钥和IV
        byte[] key1 = generateRandomBytes(16);
        byte[] key2 = generateRandomBytes(16);
        byte[] key3 = generateRandomBytes(16);
        
        byte[] iv1 = generateRandomBytes(12);
        byte[] iv2 = generateRandomBytes(12);
        byte[] iv3 = generateRandomBytes(12);

        // 发送消息给参与方1
        byte[] encryptedMessage1 = encrypt("Message for participant 1", key1, iv1);
        System.out.println("Encrypted message 1: " + Base64.getEncoder().encodeToString(encryptedMessage1));

        // 发送消息给参与方2
        byte[] encryptedMessage2 = encrypt("Message for participant 2", key2, iv2);
        System.out.println("Encrypted message 2: " + Base64.getEncoder().encodeToString(encryptedMessage2));

        // 发送消息给参与方3
        byte[] encryptedMessage3 = encrypt("Message for participant 3", key3, iv3);
        System.out.println("Encrypted message 3: " + Base64.getEncoder().encodeToString(encryptedMessage3));
    }

    private static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private static byte[] encrypt(String message, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        return cipher.doFinal(message.getBytes());
    }

}