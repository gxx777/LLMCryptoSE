import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;

public class SymmetricEncryptionCFB3 {
    
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CFB/NoPadding";
    private static final String IV = "1234567890123456"; // 16-byte initialization vector
    private static final String KEY = "abcdefghijklmnop"; // 16-byte encryption key
    
    public static String encrypt(String text) throws Exception {
        Key key = new SecretKeySpec(KEY.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes()));
        byte[] encryptedBytes = cipher.doFinal(text.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedText) throws Exception {
        Key key = new SecretKeySpec(KEY.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes()));
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            String originalText = "Hello, world!";
            String encryptedText = encrypt(originalText);
            System.out.println("Encrypted text: " + encryptedText);
            String decryptedText = decrypt(encryptedText);
            System.out.println("Decrypted text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}