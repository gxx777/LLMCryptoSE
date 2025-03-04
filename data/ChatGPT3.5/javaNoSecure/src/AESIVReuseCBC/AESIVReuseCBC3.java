import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCBC3 {

    public static void main(String[] args) {
        try {
            // Initialize secret key and IV
            String secretKey = "YourSecretKey";
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "AES");
            IvParameterSpec iv = new IvParameterSpec(new byte[16]); // Initialization Vector, should be unique for each message

            // Encrypt and send message to recipient 1
            String message1 = "Message for recipient 1";
            String encryptedMessage1 = encrypt(message1, secretKeySpec, iv);
            System.out.println("Encrypted message for recipient 1: " + encryptedMessage1);

            // Encrypt and send message to recipient 2
            String message2 = "Message for recipient 2";
            String encryptedMessage2 = encrypt(message2, secretKeySpec, iv);
            System.out.println("Encrypted message for recipient 2: " + encryptedMessage2);

            // Encrypt and send message to recipient 3
            String message3 = "Message for recipient 3";
            String encryptedMessage3 = encrypt(message3, secretKeySpec, iv);
            System.out.println("Encrypted message for recipient 3: " + encryptedMessage3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String encrypt(String message, SecretKeySpec secretKeySpec, IvParameterSpec iv) throws Exception {
        // Create and initialize AES Cipher for encryption
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);

        // Encrypt the message
        byte[] encrypted = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
}