import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;

public class AESIVReuseOFB2 {

    public static void main(String[] args) {
        try {
            // Generate AES key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey secretKey = keyGenerator.generateKey();

            // Create new IV for each participant
            IvParameterSpec ivParticipant1 = new IvParameterSpec(new byte[16]);
            IvParameterSpec ivParticipant2 = new IvParameterSpec(new byte[16]);
            IvParameterSpec ivParticipant3 = new IvParameterSpec(new byte[16]);

            // Create AES cipher in OFB mode
            Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");

            // Encrypt and send message to participant 1
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParticipant1);
            String messageToParticipant1 = "Hello Participant 1!";
            byte[] encryptedMessageToParticipant1 = cipher.doFinal(messageToParticipant1.getBytes());
            System.out.println("Encrypted message to Participant 1: " + Base64.getEncoder().encodeToString(encryptedMessageToParticipant1));

            // Encrypt and send message to participant 2
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParticipant2);
            String messageToParticipant2 = "Hello Participant 2!";
            byte[] encryptedMessageToParticipant2 = cipher.doFinal(messageToParticipant2.getBytes());
            System.out.println("Encrypted message to Participant 2: " + Base64.getEncoder().encodeToString(encryptedMessageToParticipant2));

            // Encrypt and send message to participant 3
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParticipant3);
            String messageToParticipant3 = "Hello Participant 3!";
            byte[] encryptedMessageToParticipant3 = cipher.doFinal(messageToParticipant3.getBytes());
            System.out.println("Encrypted message to Participant 3: " + Base64.getEncoder().encodeToString(encryptedMessageToParticipant3));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}