import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseOFB3 {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "AES/OFB/PKCS5Padding";
    private static final int IV_LENGTH = 16;

    // Initialize the key shared among all three participants
    private static final byte[] key = "ThisIsASecretKey".getBytes();

    // Generate random IV for encryption
    private static byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // Encrypt message using AES in OFB mode with the same key and IV for each participant
    public static String encryptMessage(String message, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(MODE);
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Decrypt message using AES in OFB mode with the same key and IV for each participant
    public static String decryptMessage(String encryptedMessage, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(MODE);
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            // Generate IV for encryption
            byte[] iv = generateIV();

            // Participant 1 sends a message
            String message1 = "Hello from Participant 1";
            String encryptedMessage1 = encryptMessage(message1, iv);
            System.out.println("Encrypted message from Participant 1: " + encryptedMessage1);

            // Participant 2 sends a message
            String message2 = "Greetings from Participant 2";
            String encryptedMessage2 = encryptMessage(message2, iv);
            System.out.println("Encrypted message from Participant 2: " + encryptedMessage2);

            // Participant 3 sends a message
            String message3 = "Hi there, Participant 3 here";
            String encryptedMessage3 = encryptMessage(message3, iv);
            System.out.println("Encrypted message from Participant 3: " + encryptedMessage3);

            // Participant 1 decrypts the message
            String decryptedMessage1 = decryptMessage(encryptedMessage1, iv);
            System.out.println("Decrypted message for Participant 1: " + decryptedMessage1);

            // Participant 2 decrypts the message
            String decryptedMessage2 = decryptMessage(encryptedMessage2, iv);
            System.out.println("Decrypted message for Participant 2: " + decryptedMessage2);

            // Participant 3 decrypts the message
            String decryptedMessage3 = decryptMessage(encryptedMessage3, iv);
            System.out.println("Decrypted message for Participant 3: " + decryptedMessage3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}