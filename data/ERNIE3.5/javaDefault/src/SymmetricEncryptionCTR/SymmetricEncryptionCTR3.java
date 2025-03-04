import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionCTR3 {

    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final int KEY_SIZE = 128; // AES key size in bits
    private static final byte[] COUNTER = new byte[16]; // Counter for CTR mode, must be block size of AES (16 bytes)

    private SecretKeySpec keySpec;
    private IvParameterSpec ivSpec;

    public SymmetricEncryptionCTR3(byte[] key) {
        if (key.length != KEY_SIZE / 8) {
            throw new IllegalArgumentException("Key size must be " + KEY_SIZE + " bits");
        }
        this.keySpec = new SecretKeySpec(key, "AES");
        this.ivSpec = new IvParameterSpec(COUNTER);
    }

    public String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String decrypt(String ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        String key = "0123456789abcdef"; // 16 characters for 128-bit AES key
        SymmetricEncryptionCTR3 encryptor = new SymmetricEncryptionCTR3(key.getBytes(StandardCharsets.UTF_8));

        String plaintext = "Hello, World!";
        String ciphertext = encryptor.encrypt(plaintext);
        String decryptedtext = encryptor.decrypt(ciphertext);

        System.out.println("Plaintext: " + plaintext);
        System.out.println("Ciphertext: " + ciphertext);
        System.out.println("Decryptedtext: " + decryptedtext);
    }
}