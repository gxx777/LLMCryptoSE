import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCBC4 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final byte[] KEY = "ThisIsASecretKey123456".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV = "ThisIsAnIV".getBytes(StandardCharsets.UTF_8);

    public static String encrypt(String message, String participant) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);

            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

            // Append the participant ID to the encrypted message
            byte[] combinedBytes = new byte[encryptedBytes.length + participant.length()];
            System.arraycopy(encryptedBytes, 0, combinedBytes, 0, encryptedBytes.length);
            System.arraycopy(participant.getBytes(StandardCharsets.UTF_8), 0, combinedBytes, encryptedBytes.length, participant.length());

            return Base64.getEncoder().encodeToString(combinedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decrypt(String encryptedMessage) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);

            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

            // Extract the participant ID and the actual encrypted message
            byte[] combinedBytes = Base64.getDecoder().decode(encryptedMessage);
            byte[] participantBytes = new byte[combinedBytes.length - 16];
            byte[] encryptedBytes = new byte[16];

            System.arraycopy(combinedBytes, 0, participantBytes, 0, participantBytes.length);
            System.arraycopy(combinedBytes, participantBytes.length, encryptedBytes, 0, encryptedBytes.length);

            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            return new String(decryptedBytes, StandardCharsets.UTF_8) + " - Participant: " + new String(participantBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        String message = "Hello, World!";
        String participant1 = "P1";
        String participant2 = "P2";
        String participant3 = "P3";

        String encryptedMessage1 = encrypt(message, participant1);
        String encryptedMessage2 = encrypt(message, participant2);
        String encryptedMessage3 = encrypt(message, participant3);

        System.out.println("Encrypted Message 1: " + encryptedMessage1);
        System.out.println("Encrypted Message 2: " + encryptedMessage2);
        System.out.println("Encrypted Message 3: " + encryptedMessage3);

        String decryptedMessage1 = decrypt(encryptedMessage1);
        String decryptedMessage2 = decrypt(encryptedMessage2);
        String decryptedMessage3 = decrypt(encryptedMessage3);

        System.out.println("Decrypted Message 1: " + decryptedMessage1);
        System.out.println("Decrypted Message 2: " + decryptedMessage2);
        System.out.println("Decrypted Message 3: " + decryptedMessage3);
    }
}