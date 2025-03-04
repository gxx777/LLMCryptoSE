import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SymmetricEncryptionCTR4 {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "CTR";
    private static final String PADDING = "NoPadding";

    public static String encrypt(String textToEncrypt, String key, String iv) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
            IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            byte[] encryptedBytes = cipher.doFinal(textToEncrypt.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String textToDecrypt, String key, String iv) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
            IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(textToDecrypt));
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        String key = "ThisIsASecretKey";
        String iv = "RandomInitVector";
        String originalText = "Hello, CTR mode encryption!";
        
        String encryptedText = encrypt(originalText, key, iv);
        System.out.println("Encrypted Text: " + encryptedText);
        
        String decryptedText = decrypt(encryptedText, key, iv);
        System.out.println("Decrypted Text: " + decryptedText);
    }
}