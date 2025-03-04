import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;

public class AESKeyReuse2 {

    public static void main(String[] args) {
        try {
            // Generate AES key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey secretKey = keyGenerator.generateKey();

            // Encode the key to Base64 for sending
            String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());

            // Participants' public keys (dummy keys for demonstration purposes)
            String participant1PublicKey = "Participant1PublicKey";
            String participant2PublicKey = "Participant2PublicKey";
            String participant3PublicKey = "Participant3PublicKey";

            // Send message to participant 1
            String messageToParticipant1 = "This is a secret message for Participant 1";
            System.out.println("Sending message to Participant 1: " + messageToParticipant1);
            String encryptedMessageToParticipant1 = encryptMessage(messageToParticipant1, participant1PublicKey, encodedKey);
            System.out.println("Encrypted message for Participant 1: " + encryptedMessageToParticipant1);

            // Send message to participant 2
            String messageToParticipant2 = "This is a secret message for Participant 2";
            System.out.println("Sending message to Participant 2: " + messageToParticipant2);
            String encryptedMessageToParticipant2 = encryptMessage(messageToParticipant2, participant2PublicKey, encodedKey);
            System.out.println("Encrypted message for Participant 2: " + encryptedMessageToParticipant2);

            // Send message to participant 3
            String messageToParticipant3 = "This is a secret message for Participant 3";
            System.out.println("Sending message to Participant 3: " + messageToParticipant3);
            String encryptedMessageToParticipant3 = encryptMessage(messageToParticipant3, participant3PublicKey, encodedKey);
            System.out.println("Encrypted message for Participant 3: " + encryptedMessageToParticipant3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String encryptMessage(String message, String publicKey, String key) throws Exception {
        // Perform AES encryption using the shared key
        SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode(key), 0, Base64.getDecoder().decode(key).length, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());

        // Dummy logic for encryption with public key (not implemented)
        // For demonstration purposes only
        // Encrypt the key with the public key and append to encrypted message
        String encryptedKey = "EncryptedKey";

        return Base64.getEncoder().encodeToString(encryptedBytes) + "||" + encryptedKey;
    }
}