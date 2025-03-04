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
        String message = "Hello, this is a secret message!";
        SecretKey secretKey = generateSecretKey();

        byte[] iv1 = generateIV();
        byte[] encryptedMessage1 = encrypt(message, secretKey, iv1);
        System.out.println("Encrypted message for participant 1: " + Base64.getEncoder().encodeToString(encryptedMessage1));

        byte[] iv2 = generateIV();
        byte[] encryptedMessage2 = encrypt(message, secretKey, iv2);
        System.out.println("Encrypted message for participant 2: " + Base64.getEncoder().encodeToString(encryptedMessage2));

        byte[] iv3 = generateIV();
        byte[] encryptedMessage3 = encrypt(message, secretKey, iv3);
        System.out.println("Encrypted message for participant 3: " + Base64.getEncoder().encodeToString(encryptedMessage3));
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

    private static byte[] encrypt(String message, SecretKey secretKey, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
        return concatenateIVAndEncryptedMessage(iv, encryptedMessage);
    }

    private static byte[] concatenateIVAndEncryptedMessage(byte[] iv, byte[] encryptedMessage) {
        ByteBuffer buffer = ByteBuffer.allocate(IV_LENGTH + encryptedMessage.length);
        buffer.put(iv);
        buffer.put(encryptedMessage);
        return buffer.array();
    }
}