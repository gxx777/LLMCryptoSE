import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseOFB3 {
    
    private static final String ALGORITHM = "AES";
    private static final String MODE = "AES/OFB/PKCS5Padding";
    
    public static void main(String[] args) throws Exception {
        
        // Generate random IV and key for each participant
        byte[] iv1 = generateIV();
        byte[] key1 = generateKey();
        
        byte[] iv2 = generateIV();
        byte[] key2 = generateKey();
        
        byte[] iv3 = generateIV();
        byte[] key3 = generateKey();
        
        // Participant 1 sending message to Participant 2
        String message1to2 = "Hello Participant 2!";
        byte[] encryptedMessage1to2 = encrypt(message1to2, key1, iv2);
        String decryptedMessage1to2 = decrypt(encryptedMessage1to2, key2, iv2);
        System.out.println("Participant 1 to Participant 2: " + decryptedMessage1to2);
        
        // Participant 2 sending message to Participant 3
        String message2to3 = "Hello Participant 3!";
        byte[] encryptedMessage2to3 = encrypt(message2to3, key2, iv3);
        String decryptedMessage2to3 = decrypt(encryptedMessage2to3, key3, iv3);
        System.out.println("Participant 2 to Participant 3: " + decryptedMessage2to3);
        
        // Participant 3 sending message to Participant 1
        String message3to1 = "Hello Participant 1!";
        byte[] encryptedMessage3to1 = encrypt(message3to1, key3, iv1);
        String decryptedMessage3to1 = decrypt(encryptedMessage3to1, key1, iv1);
        System.out.println("Participant 3 to Participant 1: " + decryptedMessage3to1);
    }
    
    private static byte[] generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
    
    private static byte[] generateKey() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return key;
    }
    
    private static byte[] encrypt(String plaintext, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        Cipher cipher = Cipher.getInstance(MODE);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        
        return cipher.doFinal(plaintext.getBytes());
    }
    
    private static String decrypt(byte[] ciphertext, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        Cipher cipher = Cipher.getInstance(MODE);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        return new String(decryptedBytes);
    }
}