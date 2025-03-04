import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM1 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128; // In bits
    private static final byte[] KEY = "ThisIsASecretKeyThisIsASecretKey".getBytes(StandardCharsets.UTF_8);

    // Generate a random IV
    private static IvParameterSpec generateIv() {
        byte[] iv = new byte[12]; // GCM IV size is 96 bits (12 bytes)
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // Encrypt a message using AES-GCM
    public static String encrypt(String plainText, String associatedData) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, associatedData.getBytes(StandardCharsets.UTF_8));
        IvParameterSpec iv = generateIv();

        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"));
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // Return the Base64 encoded cipherText along with the IV
        return Base64.getEncoder().encodeToString(iv.getIV()) + ":" + Base64.getEncoder().encodeToString(cipherText);
    }

    // Decrypt a message using AES-GCM
    public static String decrypt(String cipherTextWithIv, String associatedData) throws Exception {
        String[] parts = cipherTextWithIv.split(":");
        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] cipherText = Base64.getDecoder().decode(parts[1]);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, associatedData.getBytes(StandardCharsets.UTF_8));

        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(KEY, "AES"));
        byte[] plainText = cipher.doFinal(cipherText);

        return new String(plainText, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        String message = "Hello, World!";
        String associatedData = "Some associated data";

        // Encrypt the message
        String encryptedMessage = encrypt(message, associatedData);
        System.out.println("Encrypted message: " + encryptedMessage);

        // Decrypt the message
        String decryptedMessage = decrypt(encryptedMessage, associatedData);
        System.out.println("Decrypted message: " + decryptedMessage);
    }
}