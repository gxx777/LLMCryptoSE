import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;

public class AESKeyReuse1 {

    private static final String AES_ENCRYPTION_SCHEME = "AES";
    private static final byte[] KEY = "ThisIsASecretKey".getBytes(); // Replace with a strong key

    public static String encrypt(String valueToEncrypt) throws Exception {
        Key key = new SecretKeySpec(KEY, AES_ENCRYPTION_SCHEME);
        Cipher cipher = Cipher.getInstance(AES_ENCRYPTION_SCHEME);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(valueToEncrypt.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedValue) throws Exception {
        Key key = new SecretKeySpec(KEY, AES_ENCRYPTION_SCHEME);
        Cipher cipher = Cipher.getInstance(AES_ENCRYPTION_SCHEME);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] originalBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedValue));
        return new String(originalBytes);
    }

    public static void sendMessageToParticipant1(String message) {
        try {
            String encryptedMessage = encrypt(message);
            // Logic to send the encrypted message to Participant 1
            System.out.println("Encrypted message sent to Participant 1: " + encryptedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void sendMessageToParticipant2(String message) {
        try {
            String encryptedMessage = encrypt(message);
            // Logic to send the encrypted message to Participant 2
            System.out.println("Encrypted message sent to Participant 2: " + encryptedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void sendMessageToParticipant3(String message) {
        try {
            String encryptedMessage = encrypt(message);
            // Logic to send the encrypted message to Participant 3
            System.out.println("Encrypted message sent to Participant 3: " + encryptedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        String message = "Hello, this is a secret message!";

        sendMessageToParticipant1(message);
        sendMessageToParticipant2(message);
        sendMessageToParticipant3(message);
    }
}