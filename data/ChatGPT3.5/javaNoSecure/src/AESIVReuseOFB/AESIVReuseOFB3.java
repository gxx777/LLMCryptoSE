import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseOFB3 {
    
    private static final String AES_ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/OFB/PKCS5Padding";
    private static final byte[] IV = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}; // Initialization Vector
    private static final String SECRET_KEY = "your_secret_key"; // Change this to your secret key
    
    public static void main(String[] args) {
        try {
            String message1 = "This is a secret message from Participant 1";
            String encryptedMessage1 = encrypt(message1, 0);
            System.out.println("Encrypted message 1: " + encryptedMessage1);
            String decryptedMessage1 = decrypt(encryptedMessage1, 0);
            System.out.println("Decrypted message 1: " + decryptedMessage1);
            
            String message2 = "This is a secret message from Participant 2";
            String encryptedMessage2 = encrypt(message2, 1);
            System.out.println("Encrypted message 2: " + encryptedMessage2);
            String decryptedMessage2 = decrypt(encryptedMessage2, 1);
            System.out.println("Decrypted message 2: " + decryptedMessage2);
            
            String message3 = "This is a secret message from Participant 3";
            String encryptedMessage3 = encrypt(message3, 2);
            System.out.println("Encrypted message 3: " + encryptedMessage3);
            String decryptedMessage3 = decrypt(encryptedMessage3, 2);
            System.out.println("Decrypted message 3: " + decryptedMessage3);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static String encrypt(String message, int participant) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(), AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(IV));
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    
    private static String decrypt(String encryptedMessage, int participant) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(), AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(IV));
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes);
    }
}