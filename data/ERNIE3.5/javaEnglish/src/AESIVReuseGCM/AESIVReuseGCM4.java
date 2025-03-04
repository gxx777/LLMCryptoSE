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

public class AESIVReuseGCM4 {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128; // In bits
    private static final byte[] KEY = "ThisIsASecretKey".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV = "ThisIsAnIV".getBytes(StandardCharsets.UTF_8); // Reusable IV

    public static String encrypt(String plaintext, String recipient) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, IV);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);

        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Combine the ciphertext, authentication tag, and recipient ID into a single string
        String encryptedText = Base64.getEncoder().encodeToString(encrypted);
        String encryptedTag = Base64.getEncoder().encodeToString(cipher.getIV());
        String encryptedRecipient = recipient;

        return encryptedText + "|" + encryptedTag + "|" + encryptedRecipient;
    }

    public static String decrypt(String encryptedText, String recipient) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        String[] parts = encryptedText.split("\\|");
        byte[] ciphertext = Base64.getDecoder().decode(parts[0]);
        byte[] iv = Base64.getDecoder().decode(parts[1]);
        byte[] decrypted = null;

        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);

        try {
            decrypted = cipher.doFinal(ciphertext);
        } catch (Exception e) {
            // Handle decryption failure due to incorrect recipient or invalid ciphertext
            System.out.println("Decryption failed for recipient: " + recipient);
            return null;
        }

        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        String plaintext = "Hello, World!";
        String recipient1 = "User1";
        String recipient2 = "User2";
        String recipient3 = "User3";

        // Encrypt messages for different recipients
        String encryptedMessage1 = encrypt(plaintext, recipient1);
        String encryptedMessage2 = encrypt(plaintext, recipient2);
        String encryptedMessage3 = encrypt(plaintext, recipient3);

        System.out.println("Encrypted message for " + recipient1 + ": " + encryptedMessage1);
        System.out.println("Encrypted message for " + recipient2 + ": " + encryptedMessage2);
        System.out.println("Encrypted message for " + recipient3 + ": " + encryptedMessage3);

        // Decrypt messages for different recipients
        String decryptedMessage1 = decrypt(encryptedMessage1, recipient1);
        String decryptedMessage2 = decrypt(encryptedMessage2, recipient2);
        String decryptedMessage3 = decrypt(encryptedMessage3, recipient3);

        System.out.println("Decrypted message for " + recipient1 + ": " + decryptedMessage1);
        System.out.println("Decrypted message for " + recipient2 + ": " + decryptedMessage2);
        System.out.println("Decrypted message for " + recipient3 + ": " + decryptedMessage3);
    }
}