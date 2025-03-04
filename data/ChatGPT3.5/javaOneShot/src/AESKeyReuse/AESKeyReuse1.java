import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

public class AESKeyReuse1 {

    public static void main(String[] args) throws Exception {
        // Generate a AES key for each participant
        SecretKey participant1Key = generateAESKey();
        SecretKey participant2Key = generateAESKey();
        SecretKey participant3Key = generateAESKey();

        // Encrypt and send messages to each participant
        String message1 = "Message for Participant 1";
        String encryptedMessage1 = encryptMessage(message1, participant1Key);
        System.out.println("Encrypted message for Participant 1: " + encryptedMessage1);

        String message2 = "Message for Participant 2";
        String encryptedMessage2 = encryptMessage(message2, participant2Key);
        System.out.println("Encrypted message for Participant 2: " + encryptedMessage2);

        String message3 = "Message for Participant 3";
        String encryptedMessage3 = encryptMessage(message3, participant3Key);
        System.out.println("Encrypted message for Participant 3: " + encryptedMessage3);
    }

    private static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    private static String encryptMessage(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}