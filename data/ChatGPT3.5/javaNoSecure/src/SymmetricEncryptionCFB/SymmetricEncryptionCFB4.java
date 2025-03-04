import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricEncryptionCFB4 {
    private static final String ALGORITHM = "AES";
    private static final String MODE = "AES/CFB/NoPadding";
    private static final String IV = "1234567890123456"; // 16 bytes IV
    
    private SecretKeySpec secretKey;
    
    public SymmetricEncryptionCFB4(String key) {
        secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
    }
    
    public String encrypt(String input) throws Exception {
        Cipher cipher = Cipher.getInstance(MODE);
        IvParameterSpec iv = new IvParameterSpec(IV.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] encryptedBytes = cipher.doFinal(input.getBytes());
        return new String(encryptedBytes);
    }
    
    public String decrypt(String input) throws Exception {
        Cipher cipher = Cipher.getInstance(MODE);
        IvParameterSpec iv = new IvParameterSpec(IV.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        byte[] decryptedBytes = cipher.doFinal(input.getBytes());
        return new String(decryptedBytes);
    }
    
    public static void main(String[] args) {
        try {
            SymmetricEncryptionCFB4 encryptor = new SymmetricEncryptionCFB4("secretkey");
            
            String plainText = "Hello, world!";
            String encryptedText = encryptor.encrypt(plainText);
            System.out.println("Encrypted text: " + encryptedText);
            
            String decryptedText = encryptor.decrypt(encryptedText);
            System.out.println("Decrypted text: " + decryptedText);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}