import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESIVReuseCBC1 {
    
    // 16 bytes secret key for AES encryption
    private static final String secretKey = "1234567890123456";
    private static final String algorithm = "AES";
    
    // Encrypt message with AES in CBC mode using IV
    public static byte[] encrypt(String message, String iv) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), algorithm);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
            
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            return cipher.doFinal(message.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    // Decrypt message with AES in CBC mode using IV
    public static String decrypt(byte[] encryptedMessage, String iv) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), algorithm);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
            
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        // Example of encrypting and decrypting a message using AES in CBC mode with IV
        String message1 = "Hello from participant 1";
        String iv1 = "abcdefghijklmnop";
        byte[] encryptedMessage1 = encrypt(message1, iv1);
        System.out.println("Encrypted message 1: " + new String(encryptedMessage1));
        System.out.println("Decrypted message 1: " + decrypt(encryptedMessage1, iv1));
        
        String message2 = "Hello from participant 2";
        String iv2 = "qrstuvwxyz12345678";
        byte[] encryptedMessage2 = encrypt(message2, iv2);
        System.out.println("Encrypted message 2: " + new String(encryptedMessage2));
        System.out.println("Decrypted message 2: " + decrypt(encryptedMessage2, iv2));
        
        String message3 = "Hello from participant 3";
        String iv3 = "mnopqrst87654321";
        byte[] encryptedMessage3 = encrypt(message3, iv3);
        System.out.println("Encrypted message 3: " + new String(encryptedMessage3));
        System.out.println("Decrypted message 3: " + decrypt(encryptedMessage3, iv3));
    }
}