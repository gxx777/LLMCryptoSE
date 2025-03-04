import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESKeyReuse1 {

    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private static String encryptMessage(String message, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decryptMessage(String encryptedMessage, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        SecretKey key = generateAESKey();

        // Sender 1
        String message1 = "Hello from Sender 1";
        String encryptedMessage1 = encryptMessage(message1, key);
        System.out.println("Encrypted message from Sender 1: " + encryptedMessage1);
        String decryptedMessage1 = decryptMessage(encryptedMessage1, key);
        System.out.println("Decrypted message by Receiver 1: " + decryptedMessage1);

        // Sender 2
        String message2 = "Hi from Sender 2";
        String encryptedMessage2 = encryptMessage(message2, key);
        System.out.println("Encrypted message from Sender 2: " + encryptedMessage2);
        String decryptedMessage2 = decryptMessage(encryptedMessage2, key);
        System.out.println("Decrypted message by Receiver 2: " + decryptedMessage2);

        // Sender 3
        String message3 = "Greetings from Sender 3";
        String encryptedMessage3 = encryptMessage(message3, key);
        System.out.println("Encrypted message from Sender 3: " + encryptedMessage3);
        String decryptedMessage3 = decryptMessage(encryptedMessage3, key);
        System.out.println("Decrypted message by Receiver 3: " + decryptedMessage3);
    }
}