import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESKeyReuse4 {

    private static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128, new SecureRandom());
        return keyGenerator.generateKey();
    }

    public static String encrypt(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedMessage, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        SecretKey key = generateKey();

        // Sender 1
        String message1 = "Hello from Sender 1";
        String encryptedMessage1 = encrypt(message1, key);
        System.out.println("Encrypted message from Sender 1: " + encryptedMessage1);

        // Sender 2
        String message2 = "Greetings from Sender 2";
        String encryptedMessage2 = encrypt(message2, key);
        System.out.println("Encrypted message from Sender 2: " + encryptedMessage2);

        // Sender 3
        String message3 = "Hola from Sender 3";
        String encryptedMessage3 = encrypt(message3, key);
        System.out.println("Encrypted message from Sender 3: " + encryptedMessage3);

        // Receiver decrypts messages
        System.out.println("Decrypted message from Sender 1: " + decrypt(encryptedMessage1, key));
        System.out.println("Decrypted message from Sender 2: " + decrypt(encryptedMessage2, key));
        System.out.println("Decrypted message from Sender 3: " + decrypt(encryptedMessage3, key));
    }
}