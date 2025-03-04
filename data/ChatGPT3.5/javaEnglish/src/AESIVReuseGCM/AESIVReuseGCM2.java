import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM2 {

    private static SecretKey secretKey;
    private static byte[] iv;

    public static void main(String[] args) throws Exception {
        // Generate secret key
        secretKey = new SecretKeySpec(generateRandomBytes(16), "AES");

        // Participant 1
        String message1 = "Hello Participant 1";
        String encryptedMessage1 = encryptMessage(message1);
        System.out.println("Encrypted message for Participant 1: " + encryptedMessage1);

        // Participant 2
        String message2 = "Hello Participant 2";
        String encryptedMessage2 = encryptMessage(message2);
        System.out.println("Encrypted message for Participant 2: " + encryptedMessage2);

        // Participant 3
        String message3 = "Hello Participant 3";
        String encryptedMessage3 = encryptMessage(message3);
        System.out.println("Encrypted message for Participant 3: " + encryptedMessage3);
    }

    private static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private static String encryptMessage(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        iv = generateRandomBytes(12);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }
}