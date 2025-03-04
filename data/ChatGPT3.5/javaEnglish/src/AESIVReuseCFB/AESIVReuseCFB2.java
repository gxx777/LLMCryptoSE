import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class AESIVReuseCFB2 {

    public static void main(String[] args) {
        try {
            // Create AES key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey secretKey = keyGenerator.generateKey();

            // Generate random IV
            byte[] iv = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);

            // Initialize cipher in CFB mode
            Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
            // Encrypt and send message to participant 1
            byte[] participant1Message = "Message for Participant 1".getBytes();
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] encryptedParticipant1Message = cipher.doFinal(participant1Message);
            // Decrypt message for participant 1
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] decryptedParticipant1Message = cipher.doFinal(encryptedParticipant1Message);
            System.out.println("Decrypted Message from Participant 1: " + new String(decryptedParticipant1Message));

            // Encrypt and send message to participant 2
            byte[] participant2Message = "Message for Participant 2".getBytes();
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] encryptedParticipant2Message = cipher.doFinal(participant2Message);
            // Decrypt message for participant 2
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] decryptedParticipant2Message = cipher.doFinal(encryptedParticipant2Message);
            System.out.println("Decrypted Message from Participant 2: " + new String(decryptedParticipant2Message));

            // Encrypt and send message to participant 3
            byte[] participant3Message = "Message for Participant 3".getBytes();
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] encryptedParticipant3Message = cipher.doFinal(participant3Message);
            // Decrypt message for participant 3
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] decryptedParticipant3Message = cipher.doFinal(encryptedParticipant3Message);
            System.out.println("Decrypted Message from Participant 3: " + new String(decryptedParticipant3Message));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}