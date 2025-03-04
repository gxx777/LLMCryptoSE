import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCBC2 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final byte[] KEY = "ThisIsASecretKeyThisIsASecretKey".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV = "ThisIsAnInitializationVector".getBytes(StandardCharsets.UTF_8);

    public static String encrypt(String plainText, int partyId) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec secretKey = new SecretKeySpec(KEY, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(IV);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            // For demonstration purposes, we'll prepend the party ID to the encrypted text
            return Base64.getEncoder().encodeToString((partyId + ":" + new String(encryptedBytes)).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public static String decrypt(String encryptedText, int partyId) {
        try {
            // Extract the party ID from the encrypted text
            String[] parts = encryptedText.split(":");
            int receivedPartyId = Integer.parseInt(parts[0]);
            if (receivedPartyId != partyId) {
                throw new RuntimeException("Party ID mismatch");
            }

            byte[] encryptedBytes = Base64.getDecoder().decode(parts[1]);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec secretKey = new SecretKeySpec(KEY, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(IV);

            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            return new String(cipher.doFinal(encryptedBytes), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }

    public static void main(String[] args) {
        String message1 = "Hello from Party A!";
        String message2 = "Hello from Party B!";
        String message3 = "Hello from Party C!";

        // Encryption
        String encrypted1 = encrypt(message1, 1);
        String encrypted2 = encrypt(message2, 2);
        String encrypted3 = encrypt(message3, 3);

        System.out.println("Encrypted message 1: " + encrypted1);
        System.out.println("Encrypted message 2: " + encrypted2);
        System.out.println("Encrypted message 3: " + encrypted3);

        // Decryption
        String decrypted1 = decrypt(encrypted1, 1);
        String decrypted2 = decrypt(encrypted2, 2);
        String decrypted3 = decrypt(encrypted3, 3);

        System.out.println("Decrypted message 1: " + decrypted1);
        System.out.println("Decrypted message 2: " + decrypted2);
        System.out.println("Decrypted message 3: " + decrypted3);
    }
}