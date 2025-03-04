import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESIVReuseCFB4 {

    public static void main(String[] args) {
        try {
            // Generate random AES key and IV
            byte[] key = "0123456789abcdef".getBytes();  // 16-byte key
            byte[] iv = "fedcba9876543210".getBytes();  // 16-byte IV

            // Create AES cipher
            Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            
            // Initialize cipher for encryption
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
            
            // Encrypt message for participant 1
            byte[] message1 = "Hello participant 1!".getBytes();
            byte[] encryptedMessage1 = cipher.doFinal(message1);
            System.out.println("Encrypted message for participant 1: " + new String(encryptedMessage1));
            
            // Initialize cipher for encryption
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
            
            // Encrypt message for participant 2
            byte[] message2 = "Hello participant 2!".getBytes();
            byte[] encryptedMessage2 = cipher.doFinal(message2);
            System.out.println("Encrypted message for participant 2: " + new String(encryptedMessage2));
            
            // Initialize cipher for encryption
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
            
            // Encrypt message for participant 3
            byte[] message3 = "Hello participant 3!".getBytes();
            byte[] encryptedMessage3 = cipher.doFinal(message3);
            System.out.println("Encrypted message for participant 3: " + new String(encryptedMessage3));
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}