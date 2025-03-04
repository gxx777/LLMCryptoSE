import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

public class SymmetricEncryption2 {
    
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final String KEY = "MySecretKey"; // 16, 24, or 32 bytes key
    
    public static String encrypt(String input) throws Exception {
        Key key = new SecretKeySpec(KEY.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        byte[] encryptedBytes = cipher.doFinal(input.getBytes());
        return new String(encryptedBytes);
    }
    
    public static String decrypt(String input) throws Exception {
        Key key = new SecretKeySpec(KEY.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key);
        
        byte[] decryptedBytes = cipher.doFinal(input.getBytes());
        return new String(decryptedBytes);
    }
    
    public static void main(String[] args) {
        String input = "Hello, world!";
        
        try {
            String encrypted = encrypt(input);
            System.out.println("Encrypted: " + encrypted);
            
            String decrypted = decrypt(encrypted);
            System.out.println("Decrypted: " + decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}