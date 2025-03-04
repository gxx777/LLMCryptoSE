import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCTR4 {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CTR/NoPadding";
    
    public static byte[] encrypt(String key, byte[] iv, String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        byte[] cipherText = cipher.doFinal(plaintext.getBytes());
        
        return cipherText;
    }

    public static String decrypt(String key, byte[] iv, byte[] cipherText) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        byte[] decryptedText = cipher.doFinal(cipherText);
        
        return new String(decryptedText);
    }

    public static void main(String[] args) throws Exception {
        String key1 = "0123456789abcdef";
        String key2 = "fedcba9876543210";
        String key3 = "a1b2c3d4e5f67890";
        byte[] iv = {1, 2, 3, 4, 5, 6, 7, 8};

        String plaintext1 = "Message for participant 1";
        String plaintext2 = "Message for participant 2";
        String plaintext3 = "Message for participant 3";

        byte[] cipherText1 = encrypt(key1, iv, plaintext1);
        byte[] cipherText2 = encrypt(key2, iv, plaintext2);
        byte[] cipherText3 = encrypt(key3, iv, plaintext3);

        String decryptedText1 = decrypt(key1, iv, cipherText1);
        String decryptedText2 = decrypt(key2, iv, cipherText2);
        String decryptedText3 = decrypt(key3, iv, cipherText3);
        
        System.out.println("Decrypted text 1: " + decryptedText1);
        System.out.println("Decrypted text 2: " + decryptedText2);
        System.out.println("Decrypted text 3: " + decryptedText3);
    }
}