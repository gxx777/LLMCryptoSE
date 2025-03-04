import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseOFB3 {

    private static final String ALGORITHM = "AES/OFB/NoPadding";
    private static final byte[] KEY = "MySuperSecretKey".getBytes(StandardCharsets.UTF_8); // 16-byte key for AES-128
    private static final byte[] INITIAL_VECTOR = "MyInitialVector".getBytes(StandardCharsets.UTF_8); // IV should be unique per session

    public static void main(String[] args) {
        String message1 = "Message for Party A";
        String message2 = "Message for Party B";
        String message3 = "Message for Party C";

        String encryptedMessage1 = encryptMessage(message1);
        String encryptedMessage2 = encryptMessage(message2);
        String encryptedMessage3 = encryptMessage(message3);

        System.out.println("Encrypted message for Party A: " + encryptedMessage1);
        System.out.println("Encrypted message for Party B: " + encryptedMessage2);
        System.out.println("Encrypted message for Party C: " + encryptedMessage3);

        // Decryption (not shown here) would be done similarly using the same key and IV
    }

    public static String encryptMessage(String message) {
        try {
            // Reuse the same IV for all messages
            IvParameterSpec ivSpec = new IvParameterSpec(INITIAL_VECTOR);
            SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

            byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting message", e);
        }
    }
}