import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCFB4 {

    private static final String ALGORITHM = "AES/CFB/NoPadding";

    private byte[] key;

    public AESIVReuseCFB4(byte[] key) {
        if (key == null || key.length != 16 && key.length != 24 && key.length != 32) {
            throw new IllegalArgumentException("Invalid key size. Key size must be 128, 192, or 256 bits.");
        }
        this.key = key;
    }

    public String encrypt(String plaintext, SecureRandom random) throws Exception {
        // Generate a new random IV for each message
        byte[] iv = new byte[8]; // AES/CFB uses 8-byte IV
        random.nextBytes(iv);

        // Create cipher instance
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        // Initialize cipher for encryption
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));

        // Encrypt the plaintext
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());

        // Return the Base64 encoded ciphertext and IV concatenated
        return Base64.getEncoder().encodeToString(iv) + Base64.getEncoder().encodeToString(ciphertext);
    }

    public String decrypt(String cipherTextWithIV, SecureRandom random) throws Exception {
        // Split the received Base64 encoded ciphertext and IV
        byte[] encodedIVAndCipherText = Base64.getDecoder().decode(cipherTextWithIV);
        int ivSize = 8; // AES/CFB uses 8-byte IV
        byte[] iv = new byte[ivSize];
        byte[] ciphertext = new byte[encodedIVAndCipherText.length - ivSize];

        System.arraycopy(encodedIVAndCipherText, 0, iv, 0, ivSize);
        System.arraycopy(encodedIVAndCipherText, ivSize, ciphertext, 0, ciphertext.length);

        // Create cipher instance
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        // Initialize cipher for decryption
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));

        // Decrypt the ciphertext
        byte[] plaintext = cipher.doFinal(ciphertext);

        // Return the decrypted plaintext as a string
        return new String(plaintext);
    }

    public static void main(String[] args) throws Exception {
        // Generate a secure random key
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] key = new byte[16]; // AES-128
        random.nextBytes(key);

        // Create an instance of AESIVReuseCFB4
        AESIVReuseCFB4 aes = new AESIVReuseCFB4(key);

        // Test encryption and decryption
        String plaintext = "Hello, World!";
        String cipherTextWithIV = aes.encrypt(plaintext, random);
        String decryptedText = aes.decrypt(cipherTextWithIV, random);

        System.out.println("Plaintext: " + plaintext);
        System.out.println("Ciphertext with IV: " + cipherTextWithIV);
        System.out.println("Decrypted text: " + decryptedText);
    }
}