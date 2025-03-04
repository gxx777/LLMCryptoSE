import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCTR4 {
    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final byte[] KEY = "MySecretKey1234567890123456".getBytes(StandardCharsets.UTF_8);

    public static String encryptMessageForParticipant(String message, String participantId) throws Exception {
        // Generate a unique IV for each participant
        byte[] iv = generateIV(participantId);

        // Create a Cipher instance for AES in CTR mode
        Cipher cipher = Cipher.getInstance(ALGORITHM);

        // Initialize the Cipher with the key and IV
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"), new IvParameterSpec(iv));

        // Encrypt the message
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        // Base64 encode the encrypted message
        String encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes);

        return encryptedMessage;
    }

    public static String decryptMessageForParticipant(String encryptedMessage, String participantId) throws Exception {
        // Generate the same IV used for encryption
        byte[] iv = generateIV(participantId);

        // Create a Cipher instance for AES in CTR mode
        Cipher cipher = Cipher.getInstance(ALGORITHM);

        // Initialize the Cipher with the key and IV
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(KEY, "AES"), new IvParameterSpec(iv));

        // Decode the Base64 encoded encrypted message
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);

        // Decrypt the message
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        // Convert the decrypted bytes to a string
        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);

        return decryptedMessage;
    }

    private static byte[] generateIV(String participantId) {
        // This is a simple example, so we'll just use the participant ID as the IV.
        // In a real-world scenario, you should use a more secure method to generate the IV.
        return participantId.getBytes(StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        // Test encryption and decryption for Participant 1
        String messageForParticipant1 = "Hello, Participant 1!";
        String encryptedMessageForParticipant1 = encryptMessageForParticipant(messageForParticipant1, "Participant1");
        String decryptedMessageForParticipant1 = decryptMessageForParticipant(encryptedMessageForParticipant1, "Participant1");
        System.out.println("Participant 1: Original Message: " + messageForParticipant1);
        System.out.println("Participant 1: Encrypted Message: " + encryptedMessageForParticipant1);
        System.out.println("Participant 1: Decrypted Message: " + decryptedMessageForParticipant1);

        // Test encryption and decryption for Participant 2
        String messageForParticipant2 = "Hello, Participant 2!";
        String encryptedMessageForParticipant2 = encryptMessageForParticipant(messageForParticipant2, "Participant2");
        String decryptedMessageForParticipant2 = decryptMessageForParticipant(encryptedMessageForParticipant2, "Participant2");
        System.out.println("Participant 2: Original Message: " + messageForParticipant2);
        System.out.println("Participant 2: Encrypted Message: " + encryptedMessageForParticipant2);
        System.out.println("Participant 2: Decrypted Message: " + decryptedMessageForParticipant2);

        // Test encryption and decryption for Participant 3
        String messageForParticipant3 = "Hello, Participant 3!";
        String encryptedMessageForParticipant3 = encryptMessageForParticipant(messageForParticipant3, "Participant3");
        String decryptedMessageForParticipant3 = decryptMessageForParticipant(encryptedMessageForParticipant3, "Participant3");
        System.out.println("Participant 3: Original Message: " + messageForParticipant3);
        System.out.println("Participant 3: Encrypted Message: " + messageForParticipant3);
    }
}