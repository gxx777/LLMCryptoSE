import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseOFB2 {
    private static final String TRANSFORMATION = "AES/OFB/PKCS5Padding";
    private static final String ALGORITHM = "AES";

    public static void main(String[] args) throws Exception {
        // Generate a random AES key
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();

        // Generate a random IV
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // Create and initialize the Cipher for encryption
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

        // Message to be sent by Participant 1
        String message1 = "Hello from Participant 1";
        byte[] encryptedMessage1 = cipher.doFinal(message1.getBytes());
        System.out.println("Participant 1 sends: " + Base64.getEncoder().encodeToString(encryptedMessage1));

        // Reinitialize the Cipher for Participant 2 using the same IV
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

        // Message to be sent by Participant 2
        String message2 = "Hello from Participant 2";
        byte[] encryptedMessage2 = cipher.doFinal(message2.getBytes());
        System.out.println("Participant 2 sends: " + Base64.getEncoder().encodeToString(encryptedMessage2));

        // Reinitialize the Cipher for Participant 3 using the same IV
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

        // Message to be sent by Participant 3
        String message3 = "Hello from Participant 3";
        byte[] encryptedMessage3 = cipher.doFinal(message3.getBytes());
        System.out.println("Participant 3 sends: " + Base64.getEncoder().encodeToString(encryptedMessage3));
    }
}