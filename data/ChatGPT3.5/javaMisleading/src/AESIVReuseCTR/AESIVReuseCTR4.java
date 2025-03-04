import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCTR4 {

    private static final String key = "aesEncryptionKey";
    private static final String initVector = "encryptionIntVec";
    
    public static void main(String[] args) {
        try {
            String message1 = "Message for participant 1";
            String message2 = "Message for participant 2";
            String message3 = "Message for participant 3";
            
            // Encrypt messages with AES CTR mode
            String encryptedMessage1 = encrypt(key, initVector, message1);
            String encryptedMessage2 = encrypt(key, initVector, message2);
            String encryptedMessage3 = encrypt(key, initVector, message3);
            
            // Send encrypted messages to participants 1, 2, and 3
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String encrypt(String key, String initVector, String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}