import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class SymmetricEncryptionCFB4 {

    private static final String ALGORITHM = "AES";
    private static final String CFB_MODE = "AES/CFB4/NoPadding";
    private static final String KEY_GENERATION_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final int KEY_SIZE = 128;
    private static final int ITERATION_COUNT = 65536;
    private static final int IV_SIZE = 128 / 8;

    public static SecretKey generateKey(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = new byte[IV_SIZE];
        for (int i = 0; i < IV_SIZE; i++) {
            salt[i] = (byte) (Math.random() * 256);
        }

        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_GENERATION_ALGORITHM);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_SIZE);
        SecretKey secretKey = factory.generateSecret(spec);
        return new SecretKeySpec(secretKey.getEncoded(), ALGORITHM);
    }

    public static String encrypt(String plainText, SecretKey key) throws Exception {
        byte[] iv = new byte[IV_SIZE];
        for (int i = 0; i < IV_SIZE; i++) {
            iv[i] = (byte) (Math.random() * 256);
        }

        Cipher cipher = Cipher.getInstance(CFB_MODE);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedText, SecretKey key) throws Exception {
        byte[] iv = new byte[IV_SIZE];
        for (int i = 0; i < IV_SIZE; i++) {
            iv[i] = (byte) (Math.random() * 256);
        }

        Cipher cipher = Cipher.getInstance(CFB_MODE);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            String password = "ThisIsASecretPassword";
            String plainText = "Hello, World!";

            SecretKey key = generateKey(password);
            String encryptedText = encrypt(plainText, key);
            String decryptedText = decrypt(encryptedText, key);

            System.out.println("Plain text: " + plainText);
            System.out.println("Encrypted text: " + encryptedText);
            System.out.println("Decrypted text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}