import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM3 {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    public static void main(String[] args) throws Exception {
        // 生成密钥
        SecretKey secretKey = generateSecretKey();

        // 发送方A、B、C分别发送消息
        String messageA = "Hello, this is message from A.";
        String messageB = "Hello, this is message from B.";
        String messageC = "Hello, this is message from C.";

        // 生成随机IV
        byte[] iv = new byte[IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // 加密并发送消息
        String encryptedMessageA = encrypt(secretKey, iv, messageA);
        String encryptedMessageB = encrypt(secretKey, iv, messageB);
        String encryptedMessageC = encrypt(secretKey, iv, messageC);

        System.out.println("Encrypted messages:");
        System.out.println("A: " + encryptedMessageA);
        System.out.println("B: " + encryptedMessageB);
        System.out.println("C: " + encryptedMessageC);

        // 解密消息
        String decryptedMessageA = decrypt(secretKey, iv, encryptedMessageA);
        String decryptedMessageB = decrypt(secretKey, iv, encryptedMessageB);
        String decryptedMessageC = decrypt(secretKey, iv, encryptedMessageC);

        System.out.println("Decrypted messages:");
        System.out.println("A: " + decryptedMessageA);
        System.out.println("B: " + decryptedMessageB);
        System.out.println("C: " + decryptedMessageC);
    }

    private static SecretKey generateSecretKey() {
        byte[] key = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(key);
        return new SecretKeySpec(key, "AES");
    }

    private static String encrypt(SecretKey secretKey, byte[] iv, String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encrypted.length);
        byteBuffer.put(iv);
        byteBuffer.put(encrypted);
        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }

    private static String decrypt(SecretKey secretKey, byte[] iv, String ciphertext) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(ciphertext);
        ByteBuffer byteBuffer = ByteBuffer.wrap(decoded);
        byte[] receivedIv = new byte[IV_LENGTH];
        byteBuffer.get(receivedIv);
        byte[] receivedCiphertext = new byte[byteBuffer.remaining()];
        byteBuffer.get(receivedCiphertext);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, receivedIv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        byte[] decrypted = cipher.doFinal(receivedCiphertext);
        return new String(decrypted);
    }
}