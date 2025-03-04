import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SymmetricEncryptionCBC4 {

    private static final String transformation = "AES/CBC/PKCS5Padding";
    private static final String algorithm = "AES";
    private static final String key = "0123456789abcdef";
    private static final String iv = "fedcba9876543210";

    public static String encrypt(String plaintext) {
        try {
            SecretKey secretKey = new SecretKeySpec(key.getBytes(), algorithm);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decrypt(String ciphertext) {
        try {
            SecretKey secretKey = new SecretKeySpec(key.getBytes(), algorithm);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        String plaintext = "Hello, world!";
        String ciphertext = encrypt(plaintext);
        System.out.println("Encrypted: " + ciphertext);
        String decrypted = decrypt(ciphertext);
        System.out.println("Decrypted: " + decrypted);
    }
}