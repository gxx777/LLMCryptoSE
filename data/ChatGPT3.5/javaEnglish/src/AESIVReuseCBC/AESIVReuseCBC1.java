import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Key;
import java.util.Base64;

public class AESIVReuseCBC1 {
    
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    
    public static void main(String[] args) {
        try {
            // Generate a random 128-bit key
            byte[] key = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(key);
            SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
            
            // Generate a random IV
            byte[] iv = new byte[16];
            random.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            
            // Participant 1
            String message1 = "Hello Participant 1";
            byte[] encryptedMessage1 = encrypt(message1, secretKey, ivParameterSpec);
            System.out.println("Participant 1 received: " + decrypt(encryptedMessage1, secretKey, ivParameterSpec));
            
            // Participant 2
            String message2 = "Hello Participant 2";
            byte[] encryptedMessage2 = encrypt(message2, secretKey, ivParameterSpec);
            System.out.println("Participant 2 received: " + decrypt(encryptedMessage2, secretKey, ivParameterSpec));
            
            // Participant 3
            String message3 = "Hello Participant 3";
            byte[] encryptedMessage3 = encrypt(message3, secretKey, ivParameterSpec);
            System.out.println("Participant 3 received: " + decrypt(encryptedMessage3, secretKey, ivParameterSpec));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static byte[] encrypt(String input, Key key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(input.getBytes());
    }

    public static String decrypt(byte[] encrypted, Key key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted);
    }
}