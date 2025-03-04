import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCFB2 {

    private static final String ALGORITHM = "AES/CFB/NoPadding";

    private Key key;
    private SecureRandom random;

    public AESIVReuseCFB2(byte[] keyBytes) {
        this.key = new SecretKeySpec(keyBytes, "AES");
        this.random = new SecureRandom();
    }

    public String encrypt(String message, String participant) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            byte[] iv = new byte[cipher.getBlockSize()];
            random.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

            byte[] encrypted = cipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public String decrypt(String encryptedMessage, String participant) {
        try {
            String[] parts = encryptedMessage.split(":");
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] encrypted = Base64.getDecoder().decode(parts[1]);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

            return new String(cipher.doFinal(encrypted));
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }

    public static void main(String[] args) {
        // Example usage:
        byte[] keyBytes = "ThisIsASecretKey12345678".getBytes(); // Replace with a strong key
        AESIVReuseCFB2 aes = new AESIVReuseCFB2(keyBytes);

        // Alice sends a message
        String messageAlice = "Hello from Alice";
        String encryptedAlice = aes.encrypt(messageAlice, "Alice");
        System.out.println("Alice's encrypted message: " + encryptedAlice);

        // Bob sends a message
        String messageBob = "Hello from Bob";
        String encryptedBob = aes.encrypt(messageBob, "Bob");
        System.out.println("Bob's encrypted message: " + encryptedBob);

        // Charlie sends a message
        String messageCharlie = "Hello from Charlie";
        String encryptedCharlie = aes.encrypt(messageCharlie, "Charlie");
        System.out.println("Charlie's encrypted message: " + encryptedCharlie);

        // Decryption examples (assuming the same AES key is used for decryption)
        System.out.println("Alice's decrypted message: " + aes.decrypt(encryptedAlice, "Alice"));
        System.out.println("Bob's decrypted message: " + aes.decrypt(encryptedBob, "Bob"));
        System.out.println("Charlie's decrypted message: " + aes.decrypt(encryptedCharlie, "Charlie"));
    }
}