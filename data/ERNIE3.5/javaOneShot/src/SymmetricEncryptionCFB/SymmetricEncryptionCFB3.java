import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionCFB3 {

    private static final String ALGORITHM = "AES/CFB/NoPadding";
    private static final int KEY_SIZE = 128; // AES key size in bits
    private byte[] key;
    private byte[] iv;

    public SymmetricEncryptionCFB3() throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        key = new byte[KEY_SIZE / 8]; // AES key length in bytes
        iv = new byte[16]; // AES block size for CFB mode
        secureRandom.nextBytes(key);
        secureRandom.nextBytes(iv);
    }

    public String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    // Getter for the key (for testing purposes only)
    public byte[] getKey() {
        return key;
    }

    // Getter for the IV (for testing purposes only)
    public byte[] getIv() {
        return iv;
    }

    public static void main(String[] args) {
        try {
            SymmetricEncryptionCFB3 encryptor = new SymmetricEncryptionCFB3();

            String originalText = "This is a secret message!";
            System.out.println("Original Text: " + originalText);

            String encryptedText = encryptor.encrypt(originalText);
            System.out.println("Encrypted Text: " + encryptedText);

            String decryptedText = encryptor.decrypt(encryptedText);
            System.out.println("Decrypted Text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}