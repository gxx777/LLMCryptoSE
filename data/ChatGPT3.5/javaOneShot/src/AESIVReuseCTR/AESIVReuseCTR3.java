import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR3 {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "CTR";
    private static final String PADDING = "/CTR/NoPadding";

    private static final String[] keys = {"key1", "key2", "key3"};

    public static String encrypt(String message, String key, String iv) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + PADDING);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), ALGORITHM);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] encrypted = cipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String encryptedMessage, String key, String iv) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + PADDING);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), ALGORITHM);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            return new String(decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        String message = "Hello, world!";
        
        String iv1 = generateIV();
        String iv2 = generateIV();
        String iv3 = generateIV();
        
        String encryptedMessage1 = encrypt(message, keys[0], iv1);
        String encryptedMessage2 = encrypt(message, keys[1], iv2);
        String encryptedMessage3 = encrypt(message, keys[2], iv3);
        
        System.out.println("Encrypted Message 1: " + encryptedMessage1);
        System.out.println("Encrypted Message 2: " + encryptedMessage2);
        System.out.println("Encrypted Message 3: " + encryptedMessage3);
        
        String decryptedMessage1 = decrypt(encryptedMessage1, keys[0], iv1);
        String decryptedMessage2 = decrypt(encryptedMessage2, keys[1], iv2);
        String decryptedMessage3 = decrypt(encryptedMessage3, keys[2], iv3);
        
        System.out.println("Decrypted Message 1: " + decryptedMessage1);
        System.out.println("Decrypted Message 2: " + decryptedMessage2);
        System.out.println("Decrypted Message 3: " + decryptedMessage3);
    }

    private static String generateIV() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
    }
}