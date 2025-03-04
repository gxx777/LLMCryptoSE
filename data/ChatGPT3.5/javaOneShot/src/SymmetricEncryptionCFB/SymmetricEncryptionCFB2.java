import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionCFB2 {

    private static byte[] iv;
    private static Key key;

    public static String encrypt(String plainText, String keyString) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");

        byte[] keyBytes = keyString.getBytes();
        key = new SecretKeySpec(keyBytes, "AES");

        SecureRandom random = SecureRandom.getInstanceStrong();
        iv = new byte[cipher.getBlockSize()];
        random.nextBytes(iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedText, String keyString) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");

        byte[] keyBytes = keyString.getBytes();
        key = new SecretKeySpec(keyBytes, "AES");

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        
        return new String(decrypted);
    }

    public static void main(String[] args) throws Exception {
        String key = "yourSecretKey";
        String plainText = "Hello, world!";
        
        String encryptedText = encrypt(plainText, key);
        System.out.println("Encrypted text: " + encryptedText);
        
        String decryptedText = decrypt(encryptedText, key);
        System.out.println("Decrypted text: " + decryptedText);
    }
}