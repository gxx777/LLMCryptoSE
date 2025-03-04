import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

public class AESKeyReuse3 {

    public static void main(String[] args) {
        try {
            // Generate AES secret key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            SecretKey secretKey = keyGenerator.generateKey();

            // Convert secret key to Base64 string
            String secretKeyString = Base64.getEncoder().encodeToString(secretKey.getEncoded());

            // Participant 1 sends message to Participant 2
            String participant1Message = "Hello Participant 2";
            String encryptedMessage1 = encrypt(participant1Message, secretKey);
            String decryptedMessage1 = decrypt(encryptedMessage1, secretKey);
            System.out.println("Participant 1 encrypted message to Participant 2: " + encryptedMessage1);
            System.out.println("Participant 2 decrypted message from Participant 1: " + decryptedMessage1);

            // Participant 2 sends message to Participant 3
            String participant2Message = "Hello Participant 3";
            String encryptedMessage2 = encrypt(participant2Message, secretKey);
            String decryptedMessage2 = decrypt(encryptedMessage2, secretKey);
            System.out.println("Participant 2 encrypted message to Participant 3: " + encryptedMessage2);
            System.out.println("Participant 3 decrypted message from Participant 2: " + decryptedMessage2);

            // Participant 3 sends message to Participant 1
            String participant3Message = "Hello Participant 1";
            String encryptedMessage3 = encrypt(participant3Message, secretKey);
            String decryptedMessage3 = decrypt(encryptedMessage3, secretKey);
            System.out.println("Participant 3 encrypted message to Participant 1: " + encryptedMessage3);
            System.out.println("Participant 1 decrypted message from Participant 3: " + decryptedMessage3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Method to encrypt message using AES
    public static String encrypt(String message, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Method to decrypt message using AES
    public static String decrypt(String encryptedMessage, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }
}