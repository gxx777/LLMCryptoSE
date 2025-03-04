import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM1 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    public static void main(String[] args) throws Exception {
        // 生成密钥
        SecretKey secretKey = generateSecretKey();

        // 初始化向量
        byte[] iv = new byte[IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        // 加密消息
        String message1 = "Hello, Party 1!";
        String message2 = "Hello, Party 2!";
        String message3 = "Hello, Party 3!";

        String encryptedMessage1 = encrypt(secretKey, gcmParameterSpec, message1);
        String encryptedMessage2 = encrypt(secretKey, gcmParameterSpec, message2);
        String encryptedMessage3 = encrypt(secretKey, gcmParameterSpec, message3);

        System.out.println("Encrypted Message 1: " + encryptedMessage1);
        System.out.println("Encrypted Message 2: " + encryptedMessage2);
        System.out.println("Encrypted Message 3: " + encryptedMessage3);
    }

    private static SecretKey generateSecretKey() {
        byte[] key = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(key);
        return new SecretKeySpec(key, "AES");
    }

    private static String encrypt(SecretKey secretKey, GCMParameterSpec gcmParameterSpec, String message) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
        ByteBuffer byteBuffer = ByteBuffer.allocate(IV_LENGTH + encryptedMessage.length);
        byteBuffer.put(gcmParameterSpec.getIV());
        byteBuffer.put(encryptedMessage);
        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }
}