import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SymmetricEncryptionCFB2 {

    private static final String ALGORITHM = "AES/CFB/NoPadding";

    /**
     * Encrypts the given string using AES encryption algorithm in CFB mode.
     *
     * @param plainText The string to be encrypted.
     * @param key       The encryption key.
     * @return The encrypted string as a Base64 encoded string.
     * @throws Exception If encryption fails.
     */
    public static String encrypt(String plainText, String key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec iv = new IvParameterSpec(new byte[16]); // AES block size is 16 bytes
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * Decrypts the given encrypted string using AES decryption algorithm in CFB mode.
     *
     * @param encryptedText The encrypted string to be decrypted.
     * @param key           The decryption key.
     * @return The decrypted string.
     * @throws Exception If decryption fails.
     */
    public static String decrypt(String encryptedText, String key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec iv = new IvParameterSpec(new byte[16]); // AES block size is 16 bytes
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            String key = "ThisIsASecretKey"; // This should be a strong, random key
            String plainText = "Hello, this is a secret message!";

            String encryptedText = encrypt(plainText, key);
            System.out.println("Encrypted Text: " + encryptedText);

            String decryptedText = decrypt(encryptedText, key);
            System.out.println("Decrypted Text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}