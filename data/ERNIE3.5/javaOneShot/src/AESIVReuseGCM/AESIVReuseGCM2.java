import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM2 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128; // 16 bytes

    // Generate a random initialization vector
    private static IvParameterSpec generateIv(int length) {
        byte[] iv = new byte[length];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // Encrypt the given message using AES-GCM
    public static String encrypt(String plainText, byte[] key, byte[] iv) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmSpec);

        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(cipherText);
    }

    // Decrypt the given ciphertext using AES-GCM
    public static String decrypt(String cipherText, byte[] key, byte[] iv) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmSpec);

        byte[] decryptedText = cipher.doFinal(bytes);
        return new String(decryptedText, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            // Generate a random AES key
            byte[] key = new byte[16]; // AES-128
            new SecureRandom().nextBytes(key);

            // Generate a random IV for encryption
            byte[] iv = generateIv(12).getIV(); // GCM mode typically requires 96-bit (12 bytes) IV

            // The message to be encrypted
            String message = "Hello, GCM Mode!";

            // Encrypt the message
            String encrypted = encrypt(message, key, iv);
            System.out.println("Encrypted: " + encrypted);

            // Decrypt the message
            String decrypted = decrypt(encrypted, key, iv);
            System.out.println("Decrypted: " + decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}