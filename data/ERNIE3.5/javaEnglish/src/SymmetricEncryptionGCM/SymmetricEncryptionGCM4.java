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

public class SymmetricEncryptionGCM4 {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128; // Length of the authentication tag in bits
    private static final byte[] KEY = "MySecretKey".getBytes(StandardCharsets.UTF_8); // Replace with your own secret key
    private static final byte[] NONCE = new byte[12]; // Random nonce

    public static String encrypt(String plaintext) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, NONCE);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Combine the nonce and ciphertext
        byte[] result = new byte[NONCE.length + ciphertext.length];
        System.arraycopy(NONCE, 0, result, 0, NONCE.length);
        System.arraycopy(ciphertext, 0, result, NONCE.length, ciphertext.length);

        return Base64.getEncoder().encodeToString(result);
    }

    public static String decrypt(String encryptedText) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] nonce = new byte[12];
        byte[] ciphertext = new byte[encryptedBytes.length - nonce.length];

        System.arraycopy(encryptedBytes, 0, nonce, 0, nonce.length);
        System.arraycopy(encryptedBytes, nonce.length, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, nonce);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
        byte[] plaintext = cipher.doFinal(ciphertext);

        return new String(plaintext, StandardCharsets.UTF_8);
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