import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCTR4 {

    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final byte[] KEY = "ThisIsASecretKey12345678".getBytes(StandardCharsets.UTF_8); // 256-bit key
    private static final byte[] IV = "ThisIsAnIV12345678".getBytes(StandardCharsets.UTF_8); // 128-bit IV for CTR mode

    public static String encrypt(String plainText, int partyId) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"), new IvParameterSpec(IV));
            byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            // Optionally, you can append the party ID to the encrypted text for identification
            return Base64.getEncoder().encodeToString(encrypted) + "#" + partyId;
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public static String decrypt(String encryptedText, int partyId) {
        try {
            // Extract the party ID from the encrypted text (if appended)
            String[] parts = encryptedText.split("#");
            if (parts.length != 2) {
                throw new IllegalArgumentException("Invalid encrypted text format");
            }
            byte[] encryptedBytes = Base64.getDecoder().decode(parts[0]);
            int expectedPartyId = Integer.parseInt(parts[1]);
            if (expectedPartyId != partyId) {
                throw new IllegalArgumentException("Party ID mismatch");
            }

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(KEY, "AES"), new IvParameterSpec(IV));
            byte[] decrypted = cipher.doFinal(encryptedBytes);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }

    public static void main(String[] args) {
        // Example usage
        String message1 = "Hello from Party 1";
        String message2 = "Hello from Party 2";
        String message3 = "Hello from Party 3";

        String encrypted1 = encrypt(message1, 1);
        String encrypted2 = encrypt(message2, 2);
        String encrypted3 = encrypt(message3, 3);

        System.out.println("Encrypted message 1: " + encrypted1);
        System.out.println("Encrypted message 2: " + encrypted2);
        System.out.println("Encrypted message 3: " + encrypted3);

        String decrypted1 = decrypt(encrypted1, 1);
        String decrypted2 = decrypt(encrypted2, 2);
        String decrypted3 = decrypt(encrypted3, 3);

        System.out.println("Decrypted message 1: " + decrypted1);
        System.out.println("Decrypted message 2: " + decrypted2);
        System.out.println("Decrypted message 3: " + decrypted3);
    }
}