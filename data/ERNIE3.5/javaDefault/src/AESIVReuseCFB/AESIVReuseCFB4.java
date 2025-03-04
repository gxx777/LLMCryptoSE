import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCFB4 {
    private static final String ALGORITHM = "AES/CFB/NoPadding";
    private byte[] key;
    private byte[] iv;
    private SecureRandom random;

    public AESIVReuseCFB4(byte[] key) {
        this.key = key;
        this.iv = new byte[16]; // AES block size for CFB mode
        this.random = new SecureRandom();
        // Initialize IV with random values
        random.nextBytes(iv);
    }

    public String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // Update IV with the last block of ciphertext
        System.arraycopy(encrypted, encrypted.length - iv.length, iv, 0, iv.length);

        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedText));

        // Update IV with the last block of plaintext
        System.arraycopy(decrypted, decrypted.length - iv.length, iv, 0, iv.length);

        return new String(decrypted, StandardCharsets.UTF_8);
    }

    // Getters and setters for the key and IV (if necessary)
    // Note: IV should not be externally modifiable for security reasons

    public static void main(String[] args) throws Exception {
        // Generate a random AES key
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);

        // Create an instance of AESIVReuseCFB4
        AESIVReuseCFB4 aes = new AESIVReuseCFB4(key);

        // Encrypt some data
        String plainText = "Hello, World!";
        String encryptedText = aes.encrypt(plainText);
        System.out.println("Encrypted Text: " + encryptedText);

        // Decrypt the data
        String decryptedText = aes.decrypt(encryptedText);
        System.out.println("Decrypted Text: " + decryptedText);
    }
}