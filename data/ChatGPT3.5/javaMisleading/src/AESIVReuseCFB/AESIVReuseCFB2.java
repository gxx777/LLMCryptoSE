import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCFB2 {
    
    private static final String AES_SECRET_KEY = "secretKey1234567";
    private static final String AES_ALGORITHM = "AES";
    private static final String AES_TRANSFORMATION = "AES/CFB/PKCS5Padding";
    
    public static void main(String[] args) {
        try {
            String message1 = "Hello from Participant 1";
            String message2 = "Hello from Participant 2";
            String message3 = "Hello from Participant 3";
            
            // Generate random IV
            byte[] iv = new byte[16]; // IV length is 16 bytes for AES
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            
            // Create AES key
            SecretKeySpec secretKeySpec = new SecretKeySpec(AES_SECRET_KEY.getBytes(), AES_ALGORITHM);
            
            // Encryption
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            
            // Participant 1 encrypts message and sends to Participant 2
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] encryptedMessage1 = cipher.doFinal(message1.getBytes());
            String encodedMessage1 = Base64.getEncoder().encodeToString(encryptedMessage1);
            System.out.println("Participant 1 sends encrypted message to Participant 2: " + encodedMessage1);
            
            // Participant 2 decrypts message from Participant 1
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] decryptedMessage1 = cipher.doFinal(Base64.getDecoder().decode(encodedMessage1));
            System.out.println("Participant 2 decrypts message from Participant 1: " + new String(decryptedMessage1));
            
            // Participant 2 encrypts message and sends to Participant 3
            byte[] encryptedMessage2 = cipher.doFinal(message2.getBytes());
            String encodedMessage2 = Base64.getEncoder().encodeToString(encryptedMessage2);
            System.out.println("Participant 2 sends encrypted message to Participant 3: " + encodedMessage2);
            
            // Participant 3 decrypts message from Participant 2
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] decryptedMessage2 = cipher.doFinal(Base64.getDecoder().decode(encodedMessage2));
            System.out.println("Participant 3 decrypts message from Participant 2: " + new String(decryptedMessage2));
            
            // Participant 3 encrypts message and sends to Participant 1
            byte[] encryptedMessage3 = cipher.doFinal(message3.getBytes());
            String encodedMessage3 = Base64.getEncoder().encodeToString(encryptedMessage3);
            System.out.println("Participant 3 sends encrypted message to Participant 1: " + encodedMessage3);
            
            // Participant 1 decrypts message from Participant 3
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] decryptedMessage3 = cipher.doFinal(Base64.getDecoder().decode(encodedMessage3));
            System.out.println("Participant 1 decrypts message from Participant 3: " + new String(decryptedMessage3));
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}