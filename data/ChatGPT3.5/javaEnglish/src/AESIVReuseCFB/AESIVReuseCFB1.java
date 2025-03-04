import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCFB1 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CFB/PKCS5Padding";
    private static final int KEY_SIZE = 256;

    public static void main(String[] args) {
        try {
            // Generate a random 256-bit key
            byte[] keyBytes = new byte[KEY_SIZE / 8];
            SecureRandom random = new SecureRandom();
            random.nextBytes(keyBytes);
            Key key = new SecretKeySpec(keyBytes, ALGORITHM);

            // Initialize the Cipher object in encryption mode
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key);

            // Initialize IV for encryption
            byte[] iv = cipher.getIV();

            // Encrypt and send message to participant 1
            String message1 = "Message for participant 1";
            byte[] encryptedMessage1 = cipher.doFinal(message1.getBytes());
            System.out.println("Encrypted message for participant 1: " + Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(encryptedMessage1));

            // Encrypt and send message to participant 2
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            String message2 = "Message for participant 2";
            byte[] encryptedMessage2 = cipher.doFinal(message2.getBytes());
            System.out.println("Encrypted message for participant 2: " + Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(encryptedMessage2));

            // Encrypt and send message to participant 3
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            String message3 = "Message for participant 3";
            byte[] encryptedMessage3 = cipher.doFinal(message3.getBytes());
            System.out.println("Encrypted message for participant 3: " + Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(encryptedMessage3));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}