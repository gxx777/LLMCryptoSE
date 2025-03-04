import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseOFB3 {

    private static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    private static IvParameterSpec generateIV() {
        byte[] iv = new byte[16];
        // Generate random IV
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static String sendMessageToParticipant(String message, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedMessage);
    }

    public static void main(String[] args) {
        try {
            SecretKey key = generateKey();
            IvParameterSpec iv = generateIV();

            String message1 = "Hello Participant 1";
            String message2 = "Hello Participant 2";
            String message3 = "Hello Participant 3";

            String encryptedMessage1 = sendMessageToParticipant(message1, key, iv);
            String encryptedMessage2 = sendMessageToParticipant(message2, key, iv);
            String encryptedMessage3 = sendMessageToParticipant(message3, key, iv);

            System.out.println("Encrypted Message 1: " + encryptedMessage1);
            System.out.println("Encrypted Message 2: " + encryptedMessage2);
            System.out.println("Encrypted Message 3: " + encryptedMessage3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}