import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESIVReuseOFB1 {
    
    private static final String key = "0123456789abcdef";
    private static final String IV1 = "aaaaaaaaaaaaaaaa";
    private static final String IV2 = "bbbbbbbbbbbbbbbb";
    private static final String IV3 = "cccccccccccccccc";
    
    public static byte[] encrypt(String plainText, String key, String IV) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        return cipher.doFinal(plainText.getBytes());
    }
    
    public static String decrypt(byte[] cipherText, String key, String IV) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(cipherText);
        return new String(decryptedBytes);
    }
    
    public static void main(String[] args) {
        try {
            String message1 = "Message from participant 1";
            String message2 = "Message from participant 2";
            String message3 = "Message from participant 3";
            
            byte[] encryptedMessage1 = encrypt(message1, key, IV1);
            byte[] encryptedMessage2 = encrypt(message2, key, IV2);
            byte[] encryptedMessage3 = encrypt(message3, key, IV3);
            
            String decryptedMessage1 = decrypt(encryptedMessage1, key, IV1);
            String decryptedMessage2 = decrypt(encryptedMessage2, key, IV2);
            String decryptedMessage3 = decrypt(encryptedMessage3, key, IV3);
            
            System.out.println("Decrypted message from participant 1: " + decryptedMessage1);
            System.out.println("Decrypted message from participant 2: " + decryptedMessage2);
            System.out.println("Decrypted message from participant 3: " + decryptedMessage3);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
