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
import java.util.Base64;

public class AESIVReuseGCM4 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128; // Authentication tag length in bits
    private static final byte[] KEY = "ThisIsASecretKeyThisIsASecretKey".getBytes(StandardCharsets.UTF_8);

    public static String encrypt(String plainText, byte[] iv) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        SecretKeySpec secretKey = new SecretKeySpec(KEY, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, byte[] iv) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        SecretKeySpec secretKey = new SecretKeySpec(KEY, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] decryptedText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(decryptedText, StandardCharsets.UTF_8);
    }

    public static void sendEncryptedMessages(String[] messages, String[] receivers) throws Exception {
        if (messages.length != receivers.length) {
            throw new IllegalArgumentException("Messages and receivers arrays must have the same length");
        }

        byte[] iv = new byte[12]; // AES GCM IV size is typically 12 bytes
        for (int i = 0; i < messages.length; i++) {
            // Generate a random IV for each message
            java.security.SecureRandom random = new java.security.SecureRandom();
            random.nextBytes(iv);

            // Encrypt the message
            String encryptedMessage = encrypt(messages[i], iv);

            // Send the encrypted message and the IV to the receiver
            // Here you would implement the sending logic, which is not shown in this example
            System.out.println("Sending encrypted message to " + receivers[i] + ": " + encryptedMessage);
            System.out.println("IV for the message: " + Base64.getEncoder().encodeToString(iv));

            // In a real scenario, you would not print the IV. It should be securely transmitted alongside the encrypted message.
        }
    }

    public static void main(String[] args) {
        try {
            String[] messages = {"Hello, Receiver 1!", "Hello, Receiver 2!", "Hello, Receiver 3!"};
            String[] receivers = {"Receiver 1", "Receiver 2", "Receiver 3"};
            sendEncryptedMessages(messages, receivers);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}