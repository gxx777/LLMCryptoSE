import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionCBC4 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final byte[] KEY = generateRandomKey(16); // AES key length can be 16, 24 or 32 bytes
    private static final byte[] IV = generateRandomIV(16); // AES block size is 16 bytes

    private SymmetricEncryptionCBC4() {
        // Hide default constructor
    }

    public static String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private static byte[] generateRandomKey(int keyLength) {
        byte[] key = new byte[keyLength];
        new SecureRandom().nextBytes(key);
        return key;
    }

    private static byte[] generateRandomIV(int ivLength) {
        byte[] iv = new byte[ivLength];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static void main(String[] args) {
        try {
            String plainText = "Hello, World!";
            String encryptedText = encrypt(plainText);
            String decryptedText = decrypt(encryptedText);
            System.out.println("Plain Text: " + plainText);
            System.out.println("Encrypted Text: " + encryptedText);
            System.out.println("Decrypted Text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}