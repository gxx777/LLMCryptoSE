import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionCFB2 {

    private static final String ALGORITHM = "AES/CFB/NoPadding";
    private static final int KEY_SIZE = 128; // AES key size in bits

    // Encrypts the given plaintext using AES in CFB mode.
    public static String encrypt(String plaintext) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[KEY_SIZE / 8]; // Convert key size from bits to bytes
        byte[] iv = new byte[16]; // AES block size for CFB mode is 16 bytes

        random.nextBytes(key);
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        
        // Return the encrypted bytes as a Base64-encoded string
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // Decrypts the given ciphertext using AES in CFB mode.
    public static String decrypt(String ciphertext) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(ciphertext);

        // Extract the random key and IV used for encryption
        byte[] key = new byte[KEY_SIZE / 8];
        byte[] iv = new byte[16];
        System.arraycopy(encryptedBytes, 0, key, 0, key.length);
        System.arraycopy(encryptedBytes, key.length, iv, 0, iv.length);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] decrypted = cipher.doFinal(encryptedBytes, key.length + iv.length, encryptedBytes.length - key.length - iv.length);
        
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            String plaintext = "Hello, World!";
            String encrypted = encrypt(plaintext);
            System.out.println("Encrypted text: " + encrypted);

            String decrypted = decrypt(encrypted);
            System.out.println("Decrypted text: " + decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}