import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCBC2 {
    
    public static void main(String[] args) {
        String message = "Secret message";
        
        String participant1 = "Participant1PublicKey";
        String participant2 = "Participant2PublicKey";
        String participant3 = "Participant3PublicKey";
        
        String encryptedMessage1 = sendMessage(message, participant1);
        String encryptedMessage2 = sendMessage(message, participant2);
        String encryptedMessage3 = sendMessage(message, participant3);
        
        System.out.println("Encrypted message for Participant 1: " + encryptedMessage1);
        System.out.println("Encrypted message for Participant 2: " + encryptedMessage2);
        System.out.println("Encrypted message for Participant 3: " + encryptedMessage3);
    }
    
    public static String sendMessage(String message, String publicKey) {
        try {
            String key = "AESKey1234567890";
    
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
            IvParameterSpec iv = new IvParameterSpec(key.getBytes());
    
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            byte[] encrypted = cipher.doFinal(message.getBytes());
    
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return null;
    }
}