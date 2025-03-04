import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;

public class SymmetricEncryptionOFB4 {
    
    private static final String ALGORITHM = "AES";
    private static final String MODE = "OFB";
    private static final String PADDING = "NoPadding";
    
    private static final byte[] IV = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    
    private SecretKeySpec secretKey;

    public SymmetricEncryptionOFB4(String key) {
        secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
    }
    
    public String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(IV));
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    
    public String decrypt(String ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(IV));
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes);
    }
    
    public static void main(String[] args) {
        String key = "secretkey123456";
        String plaintext = "Hello, world!";
        
        try {
            SymmetricEncryptionOFB4 encryptor = new SymmetricEncryptionOFB4(key);
            String encryptedText = encryptor.encrypt(plaintext);
            System.out.println("Encrypted text: " + encryptedText);
            
            String decryptedText = encryptor.decrypt(encryptedText);
            System.out.println("Decrypted text: " + decryptedText);
        } catch(Exception e) {
            e.printStackTrace();
        }
    }
}