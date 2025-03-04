import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SymmetricEncryptionCBC4 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private byte[] key;
    private byte[] iv;

    public SymmetricEncryptionCBC4(byte[] key, byte[] iv) {
        this.key = key;
        this.iv = iv;
    }

    /**
     * Encrypts the given plaintext string using AES/CBC/PKCS5Padding.
     *
     * @param plaintext the string to encrypt
     * @return the encrypted string in Base64 format
     * @throws Exception if encryption fails
     */
    public String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * Decrypts the given encrypted string using AES/CBC/PKCS5Padding.
     *
     * @param encryptedText the Base64 encoded encrypted string to decrypt
     * @return the decrypted string
     * @throws Exception if decryption fails
     */
    public String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            // Generate a random key and IV for AES/CBC
            byte[] key = new byte[16]; // AES key size is 128 bits (16 bytes)
            byte[] iv = new byte[16];  // AES block size is 128 bits (16 bytes)

            // Initialize the encryption class with the key and IV
            SymmetricEncryptionCBC4 encryption = new SymmetricEncryptionCBC4(key, iv);

            // Test encryption
            String plaintext = "Hello, World!";
            String encryptedText = encryption.encrypt(plaintext);
            System.out.println("Encrypted Text: " + encryptedText);

            // Test decryption
            String decryptedText = encryption.decrypt(encryptedText);
            System.out.println("Decrypted Text: " + decryptedText);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}