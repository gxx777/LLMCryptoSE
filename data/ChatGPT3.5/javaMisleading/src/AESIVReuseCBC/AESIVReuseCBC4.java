import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESIVReuseCBC4 {
  
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    
    public static byte[] encrypt(String key, String iv, String message) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
        IvParameterSpec initializationVector = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, initializationVector);
        return cipher.doFinal(message.getBytes());
    }
    
    public static String decrypt(String key, String iv, byte[] encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
        IvParameterSpec initializationVector = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, secretKey, initializationVector);
        return new String(cipher.doFinal(encryptedMessage));
    }
    
    public static void main(String[] args) {
        String key = "1234567890123456"; // 16字节AES密钥
        String iv = "abcdefghijklmnop"; // 16字节初始向量
        
        try {
            String message1 = "Hello, participant 1!";
            byte[] encryptedMessage1 = encrypt(key, iv, message1);
            System.out.println("Encrypted message 1: " + new String(encryptedMessage1));
            String decryptedMessage1 = decrypt(key, iv, encryptedMessage1);
            System.out.println("Decrypted message 1: " + decryptedMessage1);
            
            String message2 = "Hello, participant 2!";
            byte[] encryptedMessage2 = encrypt(key, iv, message2);
            System.out.println("Encrypted message 2: " + new String(encryptedMessage2));
            String decryptedMessage2 = decrypt(key, iv, encryptedMessage2);
            System.out.println("Decrypted message 2: " + decryptedMessage2);
            
            String message3 = "Hello, participant 3!";
            byte[] encryptedMessage3 = encrypt(key, iv, message3);
            System.out.println("Encrypted message 3: " + new String(encryptedMessage3));
            String decryptedMessage3 = decrypt(key, iv, encryptedMessage3);
            System.out.println("Decrypted message 3: " + decryptedMessage3);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}