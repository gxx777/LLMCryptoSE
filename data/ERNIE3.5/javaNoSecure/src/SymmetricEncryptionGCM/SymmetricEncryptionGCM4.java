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
    private static final int TAG_LENGTH = 128; // 16 bytes
    private static final byte[] KEY = "ThisIsASecretKeyThisIsASecretKey".getBytes(StandardCharsets.UTF_8); // 32 bytes
    private static final byte[] IV = new byte[12]; // 12 bytes

    public static String encrypt(String plaintext) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, IV);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Combine the authentication tag with the ciphertext
        byte[] result = new byte[ciphertext.length + TAG_LENGTH / 8]; // TAG_LENGTH is in bits, convert to bytes        System.arraycopy(ciphertext, 0, result, 0, ciphertext.length);
        System.arraycopy(cipher.getIV(), 0, result, ciphertext.length, TAG_LENGTH / 8); // TAG_LENGTH is in bits, convert to bytes
        return Base64.getEncoder().encodeToString(result);
    }

    public static String decrypt(String ciphertext) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, IV);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");

        // Split the authentication tag from the ciphertext
        byte[] input = Base64.getDecoder().decode(ciphertext);
        byte[] ciphertextWithoutTag = new byte[input.length - TAG_LENGTH / 8]; // TAG_LENGTH is in bits, convert to bytes
        System.arraycopy(input, 0, ciphertextWithoutTag, 0, ciphertextWithoutTag.length);

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
        byte[] plaintext = cipher.doFinal(ciphertextWithoutTag);

        return new String(plaintext, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String originalText = "Hello, World!";
        String encryptedText = encrypt(originalText);
        String decryptedText = decrypt(encryptedText);

        System.out.println("Original Text: " + originalText);
        System.out.println("Encrypted Text: " + encryptedText);
        System.out.println("Decrypted Text: " + decryptedText);
    }
}