import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM4 {

    private static final int GCM_TAG_LENGTH = 16;

    public static void main(String[] args) throws Exception {
        // Generate random AES key
        byte[] aesKey = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(aesKey);
        
        // Create SecretKey object using AES key
        SecretKey secretKey = new SecretKeySpec(aesKey, "AES");
        
        // Generate random IV
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        
        // Create GCMParameterSpec with IV and tag length
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        
        // Encrypt message for participant 1
        String message1 = "Hello participant 1!";
        byte[] cipherText1 = encrypt(message1, secretKey, gcmSpec);
        
        // Encrypt message for participant 2
        String message2 = "Hello participant 2!";
        byte[] cipherText2 = encrypt(message2, secretKey, gcmSpec);
        
        // Encrypt message for participant 3
        String message3 = "Hello participant 3!";
        byte[] cipherText3 = encrypt(message3, secretKey, gcmSpec);
        
        System.out.println("Cipher text for participant 1: " + Base64.getEncoder().encodeToString(cipherText1));
        System.out.println("Cipher text for participant 2: " + Base64.getEncoder().encodeToString(cipherText2));
        System.out.println("Cipher text for participant 3: " + Base64.getEncoder().encodeToString(cipherText3));
    }

    private static byte[] encrypt(String message, SecretKey secretKey, GCMParameterSpec gcmSpec) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
        byte[] ivAndCipherText = new byte[gcmSpec.getIV().length + encryptedMessage.length];
        System.arraycopy(gcmSpec.getIV(), 0, ivAndCipherText, 0, gcmSpec.getIV().length);
        System.arraycopy(encryptedMessage, 0, ivAndCipherText, gcmSpec.getIV().length, encryptedMessage.length);
        return ivAndCipherText;
    }
}