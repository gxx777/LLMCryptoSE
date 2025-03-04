import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM4 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128; // 16 bytes for AES-256

    private byte[] key;

    public AESIVReuseGCM4(byte[] key) {
        if (key == null || key.length != 32) {
            throw new IllegalArgumentException("Key must be 256 bits (32 bytes) long.");
        }
        this.key = key;
    }

    public String encrypt(String plaintext, byte[] nonce) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, nonce);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Return the ciphertext and the authentication tag combined
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public String decrypt(String encryptedText, byte[] nonce) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, nonce);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);

        byte[] plaintext = cipher.doFinal(encryptedBytes);

        return new String(plaintext, StandardCharsets.UTF_8);
    }

    // Utility method to generate a nonce (IV)
    public static byte[] generateNonce() {
        byte[] nonce = new byte[12]; // GCM nonce should be 96 bits (12 bytes) long
        // SecureRandom to generate nonce
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    public static void main(String[] args) {
        try {
            // Generate a 256-bit key
            byte[] key = new byte[32];
            new SecureRandom().nextBytes(key);

            // Create an instance of AESIVReuseGCM4
            AESIVReuseGCM4 aesGcm = new AESIVReuseGCM4(key);

            // Generate a nonce (IV)
            byte[] nonce = AESIVReuseGCM4.generateNonce();

            // Encrypt a message
            String plaintext = "Hello, World!";
            String encrypted = aesGcm.encrypt(plaintext, nonce);
            System.out.println("Encrypted: " + encrypted);

            // Decrypt the message
            String decrypted = aesGcm.decrypt(encrypted, nonce);
            System.out.println("Decrypted: " + decrypted);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}