import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESKeyReuse1 {
    public static void main(String[] args) throws Exception {
        // Generate a random AES key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();

        // Encode the key to Base64 format
        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());

        // Create three different messages for three participants
        String message1 = "Hello, participant 1!";
        String message2 = "Hello, participant 2!";
        String message3 = "Hello, participant 3!";

        // Encrypt the messages using the same AES key
        String encryptedMessage1 = encrypt(message1, encodedKey);
        String encryptedMessage2 = encrypt(message2, encodedKey);
        String encryptedMessage3 = encrypt(message3, encodedKey);

        // Send the encrypted messages to the participants
        sendMessageToParticipant1(encryptedMessage1);
        sendMessageToParticipant2(encryptedMessage2);
        sendMessageToParticipant3(encryptedMessage3);
    }

    private static String encrypt(String message, String key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(key);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static void sendMessageToParticipant1(String message) {
        System.out.println("Sending encrypted message to participant 1: " + message);
    }

    private static void sendMessageToParticipant2(String message) {
        System.out.println("Sending encrypted message to participant 2: " + message);
    }

    private static void sendMessageToParticipant3(String message) {
        System.out.println("Sending encrypted message to participant 3: " + message);
    }
}