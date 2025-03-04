import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseOFB2 {
    
    private static final String AES_ALGORITHM = "AES";
    private static final String AES_MODE = "AES/OFB/PKCS5Padding";
    
    private static final byte[] key = "1234567890123456".getBytes(); // 16 bytes key
    private static final byte[] IV = "1234567890123456".getBytes(); // 16 bytes IV
    
    public static String encrypt(String data, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_MODE);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, AES_ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
        
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    public static String decrypt(String data, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_MODE);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, AES_ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
        
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(data));
        return new String(decrypted);
    }
    
    public static void main(String[] args) {
        try {
            String message1 = "Hello from Participant 1";
            String message2 = "Hello from Participant 2";
            String message3 = "Hello from Participant 3";
            
            byte[] iv1 = IV;
            byte[] iv2 = IV;
            byte[] iv3 = IV;
            
            String encryptedMessage1 = encrypt(message1, iv1);
            System.out.println("Encrypted Message 1: " + encryptedMessage1);
            String decryptedMessage1 = decrypt(encryptedMessage1, iv1);
            System.out.println("Decrypted Message 1: " + decryptedMessage1);
            
            String encryptedMessage2 = encrypt(message2, iv2);
            System.out.println("Encrypted Message 2: " + encryptedMessage2);
            String decryptedMessage2 = decrypt(encryptedMessage2, iv2);
            System.out.println("Decrypted Message 2: " + decryptedMessage2);
            
            String encryptedMessage3 = encrypt(message3, iv3);
            System.out.println("Encrypted Message 3: " + encryptedMessage3);
            String decryptedMessage3 = decrypt(encryptedMessage3, iv3);
            System.out.println("Decrypted Message 3: " + decryptedMessage3);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}