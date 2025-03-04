import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCBC2 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final byte[] KEY = "YourSecretKey".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV = "YourInitializationVector".getBytes(StandardCharsets.UTF_8);

    public static String encrypt(String message, String recipient) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        // Append the recipient ID to the encrypted message
        byte[] encryptedWithRecipient = new byte[encrypted.length + recipient.length()];
        System.arraycopy(encrypted, 0, encryptedWithRecipient, 0, encrypted.length);
        System.arraycopy(recipient.getBytes(StandardCharsets.UTF_8), 0, encryptedWithRecipient, encrypted.length, recipient.length());

        return Base64.getEncoder().encodeToString(encryptedWithRecipient);
    }

    public static String decrypt(String encryptedMessage) throws Exception {
        byte[] encryptedWithRecipient = Base64.getDecoder().decode(encryptedMessage);

        // Extract the recipient ID from the encrypted message
        String recipient = new String(encryptedWithRecipient, encryptedWithRecipient.length - 16, 16, StandardCharsets.UTF_8);

        // Extract the actual encrypted message
        byte[] encrypted = new byte[encryptedWithRecipient.length - 16];
        System.arraycopy(encryptedWithRecipient, 0, encrypted, 0, encrypted.length);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decrypted = cipher.doFinal(encrypted);

        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static void sendMessageToParticipant(String message, String participant) throws Exception {
        String encryptedMessage = encrypt(message, participant);
        // Send the encrypted message to the participant
        System.out.println("Sending encrypted message to " + participant + ": " + encryptedMessage);

        // Receive the decrypted message from the participant
        String decryptedMessage = decrypt(encryptedMessage);
        System.out.println("Received decrypted message from " + participant + ": " + decryptedMessage);
    }

    public static void main(String[] args) throws Exception {
        // Example usage
        String message = "Hello, this is a secret message!";
        String participant1 = "Participant1";
        String participant2 = "Participant2";
        String participant3 = "Participant3";

        sendMessageToParticipant(message, participant1);
        sendMessageToParticipant(message, participant2);
        sendMessageToParticipant(message, participant3);
    }
}