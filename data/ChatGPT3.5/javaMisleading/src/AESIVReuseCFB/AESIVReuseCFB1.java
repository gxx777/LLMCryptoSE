import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCFB1 {

    private static SecretKey secretKey;
    private static byte[] IV;

    public static void main(String[] args) {
        try {
            // Generate secret key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            secretKey = keyGenerator.generateKey();

            // Generate random IV
            SecureRandom random = new SecureRandom();
            IV = new byte[16];
            random.nextBytes(IV);

            // Sender 1 encrypts message
            String message1 = "Message from Sender 1";
            byte[] encryptedMessage1 = encrypt(message1, IV);
            String encodedEncryptedMessage1 = Base64.getEncoder().encodeToString(encryptedMessage1);
            System.out.println("Sender 1 sends encrypted message: " + encodedEncryptedMessage1);

            // Sender 2 encrypts message
            String message2 = "Message from Sender 2";
            byte[] encryptedMessage2 = encrypt(message2, IV);
            String encodedEncryptedMessage2 = Base64.getEncoder().encodeToString(encryptedMessage2);
            System.out.println("Sender 2 sends encrypted message: " + encodedEncryptedMessage2);

            // Sender 3 encrypts message
            String message3 = "Message from Sender 3";
            byte[] encryptedMessage3 = encrypt(message3, IV);
            String encodedEncryptedMessage3 = Base64.getEncoder().encodeToString(encryptedMessage3);
            System.out.println("Sender 3 sends encrypted message: " + encodedEncryptedMessage3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] encrypt(String message, byte[] IV) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(IV));
        return cipher.doFinal(message.getBytes());
    }

}