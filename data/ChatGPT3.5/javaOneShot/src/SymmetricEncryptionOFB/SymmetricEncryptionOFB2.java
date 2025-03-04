import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricEncryptionOFB2 {
    
    private static final String ALGORITHM = "AES";
    private static final String MODE = "OFB";
    private static final String PADDING = "NoPadding";
    
    public static byte[] encrypt(String key, String plaintext) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedText = cipher.doFinal(plaintext.getBytes());
        return encryptedText;
    }
    
    public static String decrypt(String key, byte[] ciphertext) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] decryptedTextBytes = cipher.doFinal(ciphertext);
        return new String(decryptedTextBytes);
    }

    public static void main(String[] args) {
        try {
            String key = "abcdefghijklmnopqrstuvwxyz123456"; // You should generate a secure key here
            String plaintext = "Hello, world!";
            
            byte[] encryptedText = encrypt(key, plaintext);
            System.out.println("Encrypted text: " + new String(encryptedText));
            
            String decryptedText = decrypt(key, encryptedText);
            System.out.println("Decrypted text: " + decryptedText);
        } catch(Exception e) {
            e.printStackTrace();
        }
    }
}