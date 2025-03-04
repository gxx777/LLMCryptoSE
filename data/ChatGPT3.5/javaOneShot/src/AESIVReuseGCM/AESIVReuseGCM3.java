import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM3 {
    
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128;
    
    public static void main(String[] args) {
        try {
            String message1 = "Message for Participant 1";
            String message2 = "Message for Participant 2";
            String message3 = "Message for Participant 3";
            
            // Generate random IV for each participant
            byte[] iv1 = generateIV();
            byte[] iv2 = generateIV();
            byte[] iv3 = generateIV();
            
            // Generate random key
            byte[] key = generateKey();
            
            // Encrypt and send messages to each participant
            String encryptedMessage1 = encrypt(message1, key, iv1);
            String encryptedMessage2 = encrypt(message2, key, iv2);
            String encryptedMessage3 = encrypt(message3, key, iv3);
            
            // Decrypt messages for each participant
            String decryptedMessage1 = decrypt(encryptedMessage1, key, iv1);
            String decryptedMessage2 = decrypt(encryptedMessage2, key, iv2);
            String decryptedMessage3 = decrypt(encryptedMessage3, key, iv3);
            
            System.out.println("Decrypted Message 1: " + decryptedMessage1);
            System.out.println("Decrypted Message 2: " + decryptedMessage2);
            System.out.println("Decrypted Message 3: " + decryptedMessage3);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static byte[] generateIV() {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
    
    private static byte[] generateKey() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return key;
    }
    
    private static String encrypt(String message, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    
    private static String decrypt(String encryptedMessage, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        
        return new String(decryptedBytes);
    }
}