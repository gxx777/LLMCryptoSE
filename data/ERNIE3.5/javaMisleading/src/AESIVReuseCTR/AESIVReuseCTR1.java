import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR1 {

    // AES key (16 bytes for AES-128, 24 bytes for AES-192, 32 bytes for AES-256)
    private static final byte[] KEY = "ThisIsASecretKey12345678".getBytes(StandardCharsets.UTF_8);

    // Shared IV for CTR mode (does not need to be secret)
    private static final byte[] IV = new byte[16];

    static {
        new SecureRandom().nextBytes(IV); // Fill the IV with random values
    }

    public static void main(String[] args) throws Exception {
        // Three different messages for three different parties
        String[] messages = {
            "Message for Party A",
            "Message for Party B",
            "Message for Party C"
        };

        // Encrypt each message
        for (String message : messages) {
            String encryptedMessage = encryptCTR(message);
            System.out.println("Encrypted message: " + encryptedMessage);
        }
    }

    private static String encryptCTR(String message) throws Exception {
        // Create a cipher instance for AES encryption in CTR mode
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

        // Secret key and IV specification
        SecretKeySpec secretKey = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        // Initialize the cipher
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        // Encrypt the message
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        // Return the Base64 encoded encrypted message
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}