import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM3 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128; // Length of the authentication tag in bits
    private static final int KEY_SIZE = 256; // Key size in bits
    private static final int IV_SIZE = 12; // Initialization vector size in bytes

    private SecretKey secretKey;
    private byte[] iv;

    public AESIVReuseGCM3() throws Exception {
        // Generate a random AES key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        secretKey = keyGenerator.generateKey();

        // Generate a random initialization vector (IV)
        SecureRandom random = new SecureRandom();
        iv = new byte[IV_SIZE];
        random.nextBytes(iv);
    }

    public String encryptMessage(String message, String recipientId) throws Exception {
        // Create a cipher instance for encryption
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

        // Encrypt the message
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        // Combine the ciphertext, authentication tag, and recipient ID into a single string
        byte[] associatedData = recipientId.getBytes(StandardCharsets.UTF_8);
        byte[] ciphertextWithTag = new byte[encryptedBytes.length + associatedData.length];
        System.arraycopy(associatedData, 0, ciphertextWithTag, 0, associatedData.length);
        System.arraycopy(encryptedBytes, 0, ciphertextWithTag, associatedData.length, encryptedBytes.length);

        // Return the Base64-encoded ciphertext
        return Base64.getEncoder().encodeToString(ciphertextWithTag);
    }

    public String decryptMessage(String encryptedMessage, String recipientId) throws Exception {
        // Extract the associated data (recipient ID) from the encrypted message
        byte[] associatedData = recipientId.getBytes(StandardCharsets.UTF_8);
        byte[] ciphertextWithTag = Base64.getDecoder().decode(encryptedMessage);

        // Extract the ciphertext and authentication tag from the encrypted message
        byte[] ciphertext = new byte[ciphertextWithTag.length - associatedData.length];
        System.arraycopy(ciphertextWithTag, associatedData.length, ciphertext, 0, ciphertext.length);

        // Create a cipher instance for decryption
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

        // Decrypt the message
        byte[] decryptedBytes = cipher.doFinal(ciphertext);

        // Return the decrypted message as a string
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        // Create an instance of AESIVReuseGCM3
        AESIVReuseGCM3 aesIvReuseGCM3 = new AESIVReuseGCM3();

        // Three different recipients
        String recipient1 = "Recipient1";
        String recipient2 = "Recipient2";
        String recipient3 = "Recipient3";

        // Messages for the recipients
        String message1 = "Hello, Recipient1!";
        String message2 = "Hello, Recipient2!";
        String message3 = "Hello, Recipient3!";

        // Encrypt messages for each recipient
        String encryptedMessage1 = aesIvReuseGCM3.encryptMessage(message1, recipient1);
        String encryptedMessage2 = aesIvReuseGCM3.encryptMessage(message2, recipient2);
        String encryptedMessage3 = aesIvReuseGCM3.encryptMessage(message3, recipient3);
    }
}