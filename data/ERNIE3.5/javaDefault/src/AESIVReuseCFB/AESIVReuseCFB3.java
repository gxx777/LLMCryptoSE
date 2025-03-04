import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCFB3 {

    private static final String ALGORITHM = "AES/CFB/NoPadding";
    private static final byte[] KEY = "ThisIsASecretKey12345678".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV = "ThisIsAnInitializationVector".getBytes(StandardCharsets.UTF_8);

    public static String encrypt(String plainText, String recipient) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(IV);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public static String decrypt(String encryptedText, String recipient) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(IV);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }

    public static void main(String[] args) {
        // Alice sends a message to Bob
        String aliceMessage = "Hello, Bob! This is a secret message.";
        String encryptedAliceMessage = encrypt(aliceMessage, "Bob");
        System.out.println("Alice sends: " + encryptedAliceMessage);

        // Bob receives and decrypts the message from Alice
        String decryptedAliceMessage = decrypt(encryptedAliceMessage, "Alice");
        System.out.println("Bob receives: " + decryptedAliceMessage);

        // Charlie tries to decrypt the message meant for Bob (this should fail if keys are different)
        String decryptedAliceMessageForCharlie = decrypt(encryptedAliceMessage, "Charlie");
        System.out.println("Charlie tries to decrypt: " + decryptedAliceMessageForCharlie);
    }
}