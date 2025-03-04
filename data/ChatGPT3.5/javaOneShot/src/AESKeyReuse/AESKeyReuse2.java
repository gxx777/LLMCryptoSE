import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESKeyReuse2 {

    private static final String AES_KEY = "mysecretkey12345";

    public static void main(String[] args) {
        String message1 = "Hello, Participant 1!";
        String message2 = "Hello, Participant 2!";
        String message3 = "Hello, Participant 3!";

        try {
            SecretKeySpec secretKey = new SecretKeySpec(AES_KEY.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");

            // Encrypt message for Participant 1
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedMessage1 = cipher.doFinal(message1.getBytes());
            System.out.println("Encrypted message for Participant 1: " + Base64.getEncoder().encodeToString(encryptedMessage1));

            // Encrypt message for Participant 2
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedMessage2 = cipher.doFinal(message2.getBytes());
            System.out.println("Encrypted message for Participant 2: " + Base64.getEncoder().encodeToString(encryptedMessage2));

            // Encrypt message for Participant 3
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedMessage3 = cipher.doFinal(message3.getBytes());
            System.out.println("Encrypted message for Participant 3: " + Base64.getEncoder().encodeToString(encryptedMessage3));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}