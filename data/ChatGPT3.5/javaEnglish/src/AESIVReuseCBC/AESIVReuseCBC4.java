import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCBC4 {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    
    private static byte[] iv = new byte[16];
    
    public static void sendMessage(String participant, String message) {
        try {
            SecretKeySpec key = new SecretKeySpec("YourSecretKey".getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] encryptedMessage = cipher.doFinal(message.getBytes());
            
            String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
            System.out.println("Sending message to " + participant + ": " + encodedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        sendMessage("Participant1", "Hello, Participant1!");
        sendMessage("Participant2", "Hello, Participant2!");
        sendMessage("Participant3", "Hello, Participant3!");
    }
}