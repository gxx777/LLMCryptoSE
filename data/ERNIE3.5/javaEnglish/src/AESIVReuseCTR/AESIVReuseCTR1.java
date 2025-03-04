import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR1 {

    private static final String ALGORITHM = "AES/CTR/NoPadding";

    public static void main(String[] args) throws Exception {
        // Generate a secret key and IV
        byte[] key = generateKey();
        byte[] iv = generateIV();

        // Messages to send to participants
        String[] messages = {
            "Message to Participant 1",
            "Message to Participant 2",
            "Message to Participant 3"
        };

        // Encrypt and send messages to participants
        for (int i = 0; i < messages.length; i++) {
            String encryptedMessage = encryptMessage(messages[i], key, iv);
            sendMessage(encryptedMessage, "Participant" + (i + 1));
        }
    }

    private static byte[] generateKey() {
        // Generate a 16-byte secret key (AES-128)
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return key;
    }

    private static byte[] generateIV() {
        // Generate a 16-byte IV (for AES-128)
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private static String encryptMessage(String message, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static void sendMessage(String encryptedMessage, String participant) {
        // Simulating sending the encrypted message to the participant
        System.out.println("Sending encrypted message to " + participant + ": " + encryptedMessage);
    }
}