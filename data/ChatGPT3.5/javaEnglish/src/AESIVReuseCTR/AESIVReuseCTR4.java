import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESIVReuseCTR4 {
    
    private SecretKey secretKey;
    private byte[] iv;

    public AESIVReuseCTR4(byte[] key) {
        secretKey = new SecretKeySpec(key, "AES");
        iv = new byte[16];
    }
    
    public void sendMessageToParticipant1(byte[] message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] encryptedMessage = cipher.doFinal(message);
        // Send encrypted message to Participant 1
    }
    
    public void sendMessageToParticipant2(byte[] message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] encryptedMessage = cipher.doFinal(message);
        // Send encrypted message to Participant 2
    }
    
    public void sendMessageToParticipant3(byte[] message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] encryptedMessage = cipher.doFinal(message);
        // Send encrypted message to Participant 3
    }

    public static void main(String[] args) {
        byte[] key = "1234567890123456".getBytes(); // 16-byte key
        AESIVReuseCTR4 aes = new AESIVReuseCTR4(key);
        
        try {
            aes.sendMessageToParticipant1("Hello Participant 1!".getBytes());
            aes.sendMessageToParticipant2("Hello Participant 2!".getBytes());
            aes.sendMessageToParticipant3("Hello Participant 3!".getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}