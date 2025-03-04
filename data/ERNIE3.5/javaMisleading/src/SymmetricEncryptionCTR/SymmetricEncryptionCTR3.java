import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionCTR3 {

    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final int KEY_SIZE = 128; // AES key size in bits

    // Generate a random AES key
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    // Encrypt the given plaintext using the provided key and an initialization vector (IV)
    public static String encrypt(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[cipher.getBlockSize()];
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Return the Base64 encoded ciphertext with the IV concatenated
        return Base64.getEncoder().encodeToString(iv) + Base64.getEncoder().encodeToString(encrypted);
    }

    // Decrypt the given ciphertext using the provided key
    public static String decrypt(String ciphertext, SecretKey key) throws Exception {
        byte[] encoded = Base64.getDecoder().decode(ciphertext);
        int ivSize = ((Cipher.getInstance(ALGORITHM)).getBlockSize());
        byte[] iv = new byte[ivSize];
        System.arraycopy(encoded, 0, iv, 0, ivSize);
        byte[] encryptedData = new byte[encoded.length - ivSize];
        System.arraycopy(encoded, ivSize, encryptedData, 0, encryptedData.length);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        return new String(cipher.doFinal(encryptedData), StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            // Generate a new AES key
            SecretKey key = generateKey();

            // String to encrypt
            String plaintext = "Hello, World!";

            // Encrypt the plaintext
            String encrypted = encrypt(plaintext, key);
            System.out.println("Encrypted Text: " + encrypted);

            // Decrypt the encrypted text
            String decrypted = decrypt(encrypted, key);
            System.out.println("Decrypted Text: " + decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}