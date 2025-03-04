import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

public class AESIVReuseCBC4 {
    
    private static final String ALGORITHM = "AES";
    private static final String MODE = "AES/CBC/PKCS5Padding";
    
    private Key key;
    private AlgorithmParameterSpec iv;
    
    public AESIVReuseCBC4(String keyString, String ivString) {
        key = new SecretKeySpec(keyString.getBytes(), ALGORITHM);
        iv = new IvParameterSpec(ivString.getBytes());
    }
    
    public String encrypt(String message) {
        try {
            Cipher cipher = Cipher.getInstance(MODE);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] encrypted = cipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    public String decrypt(String encryptedMessage) {
        try {
            Cipher cipher = Cipher.getInstance(MODE);
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            return new String(decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    public static void main(String[] args) {
        String key = "secretkey1234567";
        String iv = "1234567890abcdef";
        
        AESIVReuseCBC4 sender = new AESIVReuseCBC4(key, iv);
        AESIVReuseCBC4 receiver1 = new AESIVReuseCBC4(key, iv);
        AESIVReuseCBC4 receiver2 = new AESIVReuseCBC4(key, iv);
        AESIVReuseCBC4 receiver3 = new AESIVReuseCBC4(key, iv);
        
        String message = "Hello, this is a secret message!";
        
        String encryptedMessage1 = sender.encrypt(message);
        String encryptedMessage2 = sender.encrypt(message);
        String encryptedMessage3 = sender.encrypt(message);
        
        System.out.println("Receiver 1 decrypted message: " + receiver1.decrypt(encryptedMessage1));
        System.out.println("Receiver 2 decrypted message: " + receiver2.decrypt(encryptedMessage2));
        System.out.println("Receiver 3 decrypted message: " + receiver3.decrypt(encryptedMessage3));
    }
}