import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SymmetricEncryptionCFB2 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CFB/PKCS5Padding";
    private static final String KEY = "MySecretKey12345"; // 16字节长度的密钥
    private static final String IV = "ABCDEFGHIJKLMNOP"; // 16字节长度的IV

    public static String encrypt(String input) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            SecretKeySpec key = new SecretKeySpec(KEY.getBytes(), ALGORITHM);
            IvParameterSpec iv = new IvParameterSpec(IV.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] encryptedBytes = cipher.doFinal(input.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String input) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            SecretKeySpec key = new SecretKeySpec(KEY.getBytes(), ALGORITHM);
            IvParameterSpec iv = new IvParameterSpec(IV.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(input));
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        String originalText = "Hello, world!";
        
        // 加密
        String encryptedText = encrypt(originalText);
        System.out.println("Encrypted text: " + encryptedText);
        
        // 解密
        String decryptedText = decrypt(encryptedText);
        System.out.println("Decrypted text: " + decryptedText);
    }

}