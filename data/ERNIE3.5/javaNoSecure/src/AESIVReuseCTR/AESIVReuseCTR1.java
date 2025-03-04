import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR1 {

    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final byte[] KEY = new byte[16]; // AES key should be 16 bytes (128 bits)
    private static final byte[] IV = new byte[16];  // AES IV should be 16 bytes (128 bits)

    static {
        // Initialize the key and IV with random bytes
        new SecureRandom().nextBytes(KEY);
        new SecureRandom().nextBytes(IV);
    }

    public static String encrypt(String message, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedMessage, byte[] key, byte[] iv) throws Exception {
        byte[] decryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return new String(cipher.doFinal(decryptedBytes), StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        // Test encryption and decryption with the same IV
        String message1 = "Message for Party A";
        String message2 = "Message for Party B";
        String message3 = "Message for Party C";

        String encrypted1 = encrypt(message1, KEY, IV);
        String encrypted2 = encrypt(message2, KEY, IV);
        String encrypted3 = encrypt(message3, KEY, IV);

        System.out.println("Encrypted Message 1: " + encrypted1);
        System.out.println("Encrypted Message 2: " + encrypted2);
        System.out.println("Encrypted Message 3: " + encrypted3);

        String decrypted1 = decrypt(encrypted1, KEY, IV);
        String decrypted2 = decrypt(encrypted2, KEY, IV);
        String decrypted3 = decrypt(encrypted3, KEY, IV);

        System.out.println("Decrypted Message 1: " + decrypted1);
        System.out.println("Decrypted Message 2: " + decrypted2);
        System.out.println("Decrypted Message 3: " + decrypted3);
    }
}