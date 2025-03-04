import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionCFB2 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CFB/NoPadding";
    private static final int IV_SIZE = 16;
    private static final int KEY_SIZE = 32;

    public static String encrypt(String plainText, String key) throws Exception {
        if (key == null || key.length() != KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key size. Key must be 32 characters long.");
        }

        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        byte[] encryptedWithIv = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
        System.arraycopy(encrypted, 0, encryptedWithIv, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(encryptedWithIv);
    }

    public static String decrypt(String encryptedText, String key) throws Exception {
        if (key == null || key.length() != KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key size. Key must be 32 characters long.");
        }

        byte[] encryptedWithIv = Base64.getDecoder().decode(encryptedText);
        if (encryptedWithIv.length < IV_SIZE) {
            throw new IllegalArgumentException("Invalid encrypted text.");
        }

        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(encryptedWithIv, 0, iv, 0, iv.length);
        int encryptedSize = encryptedWithIv.length - iv.length;
        byte[] encrypted = new byte[encryptedSize];
        System.arraycopy(encryptedWithIv, iv.length, encrypted, 0, encryptedSize);

        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            String key = "abcdefghijklmnopqrstuvwxyz123456"; // 32 characters
            String plainText = "Hello, World!";
            String encryptedText = encrypt(plainText, key);
            System.out.println("Encrypted: " + encryptedText);
            String decryptedText = decrypt(encryptedText, key);
            System.out.println("Decrypted: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}