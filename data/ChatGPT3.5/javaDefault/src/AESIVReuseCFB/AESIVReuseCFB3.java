import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESIVReuseCFB3 {
    
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CFB/PKCS5Padding";
    
    private static final byte[] keyBytes = "1234567890abcdef".getBytes();
    private static final byte[] ivBytes = "abcdef9876543210".getBytes();
    
    public static void sendMessage(String message, int participant) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
        
        System.out.println("Participant " + participant + " sent message: " + new String(encryptedMessage));
    }
    
    public static void main(String[] args) {
        try {
            sendMessage("Hello from Participant 1", 1);
            sendMessage("Greetings from Participant 2", 2);
            sendMessage("Salutations from Participant 3", 3);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}