import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionCBC2 {

    private static final String ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 128;
    private static final int IV_SIZE = 16;

    public static String encrypt(String plainText, String key) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        byte[] encryptedWithIv = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
        System.arraycopy(encrypted, 0, encryptedWithIv, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(encryptedWithIv);
    }

    public static String decrypt(String encryptedText, String key) throws Exception {
        byte[] encryptedWithIv = Base64.getDecoder().decode(encryptedText);
        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(encryptedWithIv, 0, iv, 0, iv.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        byte[] encrypted = new byte[encryptedWithIv.length - iv.length];
        System.arraycopy(encryptedWithIv, iv.length, encrypted, 0, encrypted.length);

        SecretKey secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        String key = "ThisIsASecretKey"; // 16 bytes for AES-128
        String plainText = "Hello, World!";

        String encryptedText = encrypt(plainText, key);
        System.out.println("Encrypted: " + encryptedText);

        String decryptedText = decrypt(encryptedText, key);
        System.out.println("Decrypted: " + decryptedText);
    }
}