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
import java.util.Base64;

public class SymmetricEncryptionGCM1 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128; // Length of the authentication tag in bits
    private static final byte[] KEY = "ThisIsASecretKey1234567890".getBytes(StandardCharsets.UTF_8); // Replace with your own secret key
    private static final byte[] IV = new byte[12]; // Initialization Vector

    public static String encrypt(String plaintext) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
        SecretKeySpec secretKey = new SecretKeySpec(KEY, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, IV);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        int tagLengthInBytes = TAG_LENGTH / 8;

        // Combine the ciphertext, authentication tag, and initialization vector
        byte[] result = new byte[ciphertext.length + tagLengthInBytes + IV.length];
        System.arraycopy(ciphertext, 0, result, 0, ciphertext.length);
        System.arraycopy(gcmParameterSpec.getIV(), 0, result, ciphertext.length, IV.length);
        System.arraycopy(cipher.getIV(), 0, result, ciphertext.length + IV.length, tagLengthInBytes);

        return Base64.getEncoder().encodeToString(result);
    }

    public static String decrypt(String encryptedText) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);

        SecretKeySpec secretKey = new SecretKeySpec(KEY, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, encryptedBytes.clone(), 0, encryptedBytes.length - TAG_LENGTH / 8);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

        byte[] plaintextBytes = cipher.doFinal(encryptedBytes, 0, encryptedBytes.length - TAG_LENGTH / 8);

        return new String(plaintextBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String plaintext = "Hello, World!";
        String encryptedText = encrypt(plaintext);
        String decryptedText = decrypt(encryptedText);

        System.out.println("Plaintext: " + plaintext);
        System.out.println("Encrypted Text: " + encryptedText);
        System.out.println("Decrypted Text: " + decryptedText);
    }
}