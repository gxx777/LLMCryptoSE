import javax.crypto.Cipher;
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
        String message1 = "Hello, participant 1!";
        String message2 = "Hello, participant 2!";
        String message3 = "Hello, participant 3!";

        byte[] key = generateRandomBytes(256 / 8); // 256-bit key
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        byte[] iv = generateRandomBytes(IV_LENGTH);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);

        byte[] encryptedMessage1 = cipher.doFinal(message1.getBytes());
        byte[] encryptedMessage2 = cipher.doFinal(message2.getBytes());
        byte[] encryptedMessage3 = cipher.doFinal(message3.getBytes());

        System.out.println("Encrypted message for participant 1: " + Base64.getEncoder().encodeToString(encryptedMessage1));
        System.out.println("Encrypted message for participant 2: " + Base64.getEncoder().encodeToString(encryptedMessage2));
        System.out.println("Encrypted message for participant 3: " + Base64.getEncoder().encodeToString(encryptedMessage3));
    }

    private static byte[] generateRandomBytes(int length) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[length];
        secureRandom.nextBytes(randomBytes);
        return randomBytes;
    }
}