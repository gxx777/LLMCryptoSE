import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SymmetricEncryptionCBC3 {

    private static final String ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String KEY = "abcdefghijklmnop"; // 16 bytes key for AES-128

    public static String encrypt(String plainText) throws Exception {
        byte[] clean = plainText.getBytes();

        SecretKey secretKey = new SecretKeySpec(KEY.getBytes(), ALGORITHM);
        IvParameterSpec ivparameterSpec = new IvParameterSpec(KEY.getBytes());

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivparameterSpec);

        byte[] encrypted = cipher.doFinal(clean);

        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedText) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);

        SecretKey secretKey = new SecretKeySpec(KEY.getBytes(), ALGORITHM);
        IvParameterSpec ivparameterSpec = new IvParameterSpec(KEY.getBytes());

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivparameterSpec);

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            String plainText = "Hello, World!";
            System.out.println("Original Text: " + plainText);

            String encryptedText = encrypt(plainText);
            System.out.println("Encrypted Text: " + encryptedText);

            String decryptedText = decrypt(encryptedText);
            System.out.println("Decrypted Text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}