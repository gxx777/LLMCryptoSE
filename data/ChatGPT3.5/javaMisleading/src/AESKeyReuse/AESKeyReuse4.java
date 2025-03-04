import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESKeyReuse4 {

    public static void main(String[] args) {
        try {
            // Generate a AES key
            SecretKeySpec key = new SecretKeySpec("passwordpassword".getBytes(), "AES");

            // Participant A sends message to Participant B
            String messageAB = "Message from A to B";
            String encryptedMessageAB = encrypt(messageAB, key);
            String decryptedMessageAB = decrypt(encryptedMessageAB, key);
            System.out.println("Participant A sends message to Participant B: " + decryptedMessageAB);

            // Participant B sends message to Participant C
            String messageBC = "Message from B to C";
            String encryptedMessageBC = encrypt(messageBC, key);
            String decryptedMessageBC = decrypt(encryptedMessageBC, key);
            System.out.println("Participant B sends message to Participant C: " + decryptedMessageBC);

            // Participant C sends message to Participant A
            String messageCA = "Message from C to A";
            String encryptedMessageCA = encrypt(messageCA, key);
            String decryptedMessageCA = decrypt(encryptedMessageCA, key);
            System.out.println("Participant C sends message to Participant A: " + decryptedMessageCA);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String encrypt(String message, SecretKeySpec key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedMessage, SecretKeySpec key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }
}