import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class AESKeyReuse4 {
    
    private static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }
    
    private static byte[] encryptMessage(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message.getBytes());
    }
    
    private static String decryptMessage(byte[] encryptedMessage, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    }
    
    public static void main(String[] args) throws Exception {
        // Generate AES key
        SecretKey aesKey = generateAESKey();
        
        // Simulate three different entities sending messages
        String message1 = "Message from entity 1";
        String message2 = "Message from entity 2";
        String message3 = "Message from entity 3";
        
        // Encrypt and decrypt messages for each entity using the same AES key
        byte[] encryptedMessage1 = encryptMessage(message1, aesKey);
        byte[] encryptedMessage2 = encryptMessage(message2, aesKey);
        byte[] encryptedMessage3 = encryptMessage(message3, aesKey);
        
        String decryptedMessage1 = decryptMessage(encryptedMessage1, aesKey);
        String decryptedMessage2 = decryptMessage(encryptedMessage2, aesKey);
        String decryptedMessage3 = decryptMessage(encryptedMessage3, aesKey);
        
        // Print decrypted messages
        System.out.println("Decrypted message from entity 1: " + decryptedMessage1);
        System.out.println("Decrypted message from entity 2: " + decryptedMessage2);
        System.out.println("Decrypted message from entity 3: " + decryptedMessage3);
    }
}