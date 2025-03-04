import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR1 {

    public static void main(String[] args) throws Exception {
        String secretKey = "YourSecretKey";
        
        // Create a secure random IV
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);

        // Create a SecretKeySpec using the secret key
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "AES");

        // Create an AES cipher in CTR mode
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

        // Message to be sent to Participant 1
        String message1 = "Hello Participant 1!";
        byte[] encryptedMessage1 = cipher.doFinal(message1.getBytes());
        String encodedMessage1 = Base64.getEncoder().encodeToString(encryptedMessage1);

        // Message to be sent to Participant 2
        String message2 = "Hello Participant 2!";
        byte[] encryptedMessage2 = cipher.doFinal(message2.getBytes());
        String encodedMessage2 = Base64.getEncoder().encodeToString(encryptedMessage2);

        // Message to be sent to Participant 3
        String message3 = "Hello Participant 3!";
        byte[] encryptedMessage3 = cipher.doFinal(message3.getBytes());
        String encodedMessage3 = Base64.getEncoder().encodeToString(encryptedMessage3);

        System.out.println("Encoded message to Participant 1: " + encodedMessage1);
        System.out.println("Encoded message to Participant 2: " + encodedMessage2);
        System.out.println("Encoded message to Participant 3: " + encodedMessage3);
    }
}