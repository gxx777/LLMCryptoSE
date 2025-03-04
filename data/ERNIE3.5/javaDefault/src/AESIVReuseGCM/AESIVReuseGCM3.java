import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESIVReuseGCM3 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128; // Authentication tag length in bits

    private SecretKeySpec key;
    private byte[] iv;

    public AESIVReuseGCM3(byte[] keyBytes) throws NoSuchAlgorithmException, InvalidKeyException {
        this.key = new SecretKeySpec(keyBytes, "AES");
        this.iv = new byte[12]; // AES GCM IV size is 12 bytes
        // For security, you should generate a random IV for each encryption operation
        // Here we are using a fixed IV for demonstration purposes only
        // In a real application, use SecureRandom to generate the IV
    }

    public String encrypt(String plaintext, String associatedData) throws Exception {
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);

        byte[] cipherText = cipher.doFinal((plaintext + associatedData).getBytes(StandardCharsets.UTF_8));
        byte[] authTag = cipher.getIV(); // GCM IV is the same as the authentication tag

        return Base64.getEncoder().encodeToString(cipherText) + ":" + Base64.getEncoder().encodeToString(authTag);
    }

    public String decrypt(String encryptedText) throws Exception {
        String[] parts = encryptedText.split(":");
        byte[] cipherText = Base64.getDecoder().decode(parts[0]);
        byte[] authTag = Base64.getDecoder().decode(parts[1]);

        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, authTag);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);

        byte[] decryptedBytes = cipher.doFinal(cipherText);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        // Generate a random AES key for demonstration purposes
        byte[] keyBytes = new byte[16]; // AES key size is 16 bytes for AES-256
        // In a real application, you should securely generate and store the key

        AESIVReuseGCM3 aes = new AESIVReuseGCM3(keyBytes);

        // Encryption
        String message = "Hello, World!";
        String associatedData = "Additional Authenticated Data";
        String encrypted = aes.encrypt(message, associatedData);
        System.out.println("Encrypted: " + encrypted);

        // Decryption
        String decrypted = aes.decrypt(encrypted);
        System.out.println("Decrypted: " + decrypted);
    }
}