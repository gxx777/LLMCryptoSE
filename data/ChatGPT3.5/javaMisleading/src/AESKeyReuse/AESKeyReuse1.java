import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;

public class AESKeyReuse1 {

    public static void main(String[] args) throws Exception {
        
        // Generate AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();
        
        // Alice encrypts message for Bob
        String messageToBob = "Hello Bob, this is a secret message!";
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedMessageToBob = cipher.doFinal(messageToBob.getBytes());
        
        // Bob decrypts message from Alice
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedMessageFromAlice = cipher.doFinal(encryptedMessageToBob);
        System.out.println("Message from Alice to Bob: " + new String(decryptedMessageFromAlice));
        
        // Charlie encrypts message for Alice
        String messageToAlice = "Hi Alice, this is a confidential message!";
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedMessageToAlice = cipher.doFinal(messageToAlice.getBytes());
        
        // Alice decrypts message from Charlie
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedMessageFromCharlie = cipher.doFinal(encryptedMessageToAlice);
        System.out.println("Message from Charlie to Alice: " + new String(decryptedMessageFromCharlie));
    }
}