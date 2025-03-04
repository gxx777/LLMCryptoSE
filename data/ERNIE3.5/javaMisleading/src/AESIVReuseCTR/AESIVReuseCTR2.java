import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESIVReuseCTR2 {

    private static final String ALGORITHM = "AES/CTR/NoPadding";

    private SecretKey secretKey;
    private IvParameterSpec iv;

    public AESIVReuseCTR2() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256); // Use 256-bit AES
        secretKey = keyGenerator.generateKey();

        // Generate a random IV for each participant
        byte[] ivBytes = new byte[16]; // AES block size is 16 bytes
        // In a real-world scenario, use a secure random generator to populate ivBytes
        // Here, for simplicity, we'll just use zeros
        // System.arraycopy(new byte[]{/* random bytes */}, 0, ivBytes, 0, ivBytes.length);
        this.iv = new IvParameterSpec(ivBytes);
    }

    public String encrypt(String message, int participantId) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String encryptedMessage, int participantId) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            AESIVReuseCTR2 aes = new AESIVReuseCTR2();

            // Participant 1
            String message1 = "Hello from Participant 1!";
            String encrypted1 = aes.encrypt(message1, 1);
            String decrypted1 = aes.decrypt(encrypted1, 1);

            // Participant 2
            String message2 = "Hello from Participant 2!";
            String encrypted2 = aes.encrypt(message2, 2);
            String decrypted2 = aes.decrypt(encrypted2, 2);

            // Participant 3
            String message3 = "Hello from Participant 3!";
            String encrypted3 = aes.encrypt(message3, 3);
            String decrypted3 = aes.decrypt(encrypted3, 3);

            System.out.println("Participant 1: Original - " + message1 + ", Decrypted - " + decrypted1);
            System.out.println("Participant 2: Original - " + message2 + ", Decrypted - " + decrypted2);
            System.out.println("Participant 3: Original - " + message3 + ", Decrypted - " + decrypted3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}