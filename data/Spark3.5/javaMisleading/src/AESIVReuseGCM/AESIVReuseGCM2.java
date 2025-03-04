import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM2 {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    public static void main(String[] args) throws Exception {
        // Generate a random secret key
        SecretKey secretKey = generateSecretKey();

        // Generate a random initialization vector (IV)
        byte[] iv = generateIV();

        // Encrypt and send messages for three different parties
        String message1 = "Hello, Party 1!";
        String message2 = "Hello, Party 2!";
        String message3 = "Hello, Party 3!";

        byte[] encryptedMessage1 = encrypt(secretKey, iv, message1);
        byte[] encryptedMessage2 = encrypt(secretKey, iv, message2);
        byte[] encryptedMessage3 = encrypt(secretKey, iv, message3);

        System.out.println("Encrypted Message 1: " + Base64.getEncoder().encodeToString(encryptedMessage1));
        System.out.println("Encrypted Message 2: " + Base64.getEncoder().encodeToString(encryptedMessage2));
        System.out.println("Encrypted Message 3: " + Base64.getEncoder().encodeToString(encryptedMessage3));
    }

    private static SecretKey generateSecretKey() {
        byte[] keyBytes = new byte[16];
        new SecureRandom().nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private static byte[] encrypt(SecretKey secretKey, byte[] iv, String message) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
        return ByteBuffer.allocate(iv.length + encryptedMessage.length).put(iv).put(encryptedMessage).array();
    }
}