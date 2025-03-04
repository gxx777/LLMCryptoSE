import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionCFB1 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CFB/PKCS5Padding";
    private static final int IV_LENGTH = 16;
    private static final String KEY = "YourSecretKey";

    public static String encrypt(String plainText) throws Exception {
        Key key = new SecretKeySpec(KEY.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
        
        return Base64.getEncoder().encodeToString(combined);
    }

    public static String decrypt(String encryptedText) throws Exception {
        Key key = new SecretKeySpec(KEY.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);

        byte[] combined = Base64.getDecoder().decode(encryptedText);
        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(combined, 0, iv, 0, IV_LENGTH);
        
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        
        byte[] encrypted = new byte[combined.length - IV_LENGTH];
        System.arraycopy(combined, IV_LENGTH, encrypted, 0, combined.length - IV_LENGTH);
        
        byte[] decrypted = cipher.doFinal(encrypted);
        
        return new String(decrypted);
    }

    public static void main(String[] args) throws Exception {
        String originalText = "Hello, this is a secret message!";
        String encryptedText = encrypt(originalText);
        System.out.println("Encrypted text: " + encryptedText);
        String decryptedText = decrypt(encryptedText);
        System.out.println("Decrypted text: " + decryptedText);
    }
}