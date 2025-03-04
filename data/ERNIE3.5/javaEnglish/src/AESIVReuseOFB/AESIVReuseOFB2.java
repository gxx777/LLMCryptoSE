import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;

public class AESIVReuseOFB2 {

    private static final String ALGORITHM = "AES/OFB/NoPadding";
    private static final byte[] KEY = "ThisIsASecretKey".getBytes(); // Replace with your own key
    private static final byte[] IV = "ThisIsAnIV".getBytes(); // Replace with your own IV

    public static String encrypt(String message, String participantId) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            Key key = new SecretKeySpec(KEY, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(IV);

            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] encryptedBytes = cipher.doFinal(message.getBytes());

            // Append participant ID to the encrypted message
            String encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes) + "|" + participantId;
            return encryptedMessage;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decrypt(String encryptedMessage, String participantId) {
        try {
            String[] parts = encryptedMessage.split("\\|");
            byte[] encryptedBytes = Base64.getDecoder().decode(parts[0]);
            String expectedParticipantId = parts[1];

            if (!expectedParticipantId.equals(participantId)) {
                throw new IllegalArgumentException("Participant ID mismatch");
            }

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            Key key = new SecretKeySpec(KEY, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(IV);

            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        String message = "Hello, this is a secret message!";

        // Encrypt message for participant 1
        String encryptedMessage1 = encrypt(message, "Participant1");
        System.out.println("Encrypted message for Participant 1: " + encryptedMessage1);

        // Encrypt message for participant 2
        String encryptedMessage2 = encrypt(message, "Participant2");
        System.out.println("Encrypted message for Participant 2: " + encryptedMessage2);

        // Encrypt message for participant 3
        String encryptedMessage3 = encrypt(message, "Participant3");
        System.out.println("Encrypted message for Participant 3: " + encryptedMessage3);

        // Decrypt messages for each participant
        String decryptedMessage1 = decrypt(encryptedMessage1, "Participant1");
        System.out.println("Decrypted message for Participant 1: " + decryptedMessage1);

        String decryptedMessage2 = decrypt(encryptedMessage2, "Participant2");
        System.out.println("Decrypted message for Participant 2: " + decryptedMessage2);

        String decryptedMessage3 = decrypt(encryptedMessage3, "Participant3");
        System.out.println("Decrypted message for Participant 3: " + decryptedMessage3);
    }
}