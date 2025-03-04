import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class AESKeyReuse2 {
    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    public static byte[] encryptMessage(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message.getBytes());
    }

    public static String decryptMessage(byte[] encryptedMessage, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        // Generate AES key
        SecretKey key = generateAESKey();

        // Simulate three different participants exchanging messages
        String message1 = "Message from Participant 1";
        byte[] encryptedMessage1 = encryptMessage(message1, key);
        String decryptedMessage1 = decryptMessage(encryptedMessage1, key);

        String message2 = "Message from Participant 2";
        byte[] encryptedMessage2 = encryptMessage(message2, key);
        String decryptedMessage2 = decryptMessage(encryptedMessage2, key);

        String message3 = "Message from Participant 3";
        byte[] encryptedMessage3 = encryptMessage(message3, key);
        String decryptedMessage3 = decryptMessage(encryptedMessage3, key);

        // Print decrypted messages
        System.out.println("Decrypted Message 1: " + decryptedMessage1);
        System.out.println("Decrypted Message 2: " + decryptedMessage2);
        System.out.println("Decrypted Message 3: " + decryptedMessage3);
    }
}