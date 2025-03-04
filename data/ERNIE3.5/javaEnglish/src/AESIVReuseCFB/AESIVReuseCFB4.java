import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCFB4 {
    private static final String ALGORITHM = "AES/CFB/NoPadding";
    private static final byte[] KEY = "MySecretKey".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV = "MyReusableIV".getBytes(StandardCharsets.UTF_8);

    public static String encrypt(String message, String recipient) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"), new IvParameterSpec(IV));

        byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedMessage, String recipient) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(KEY, "AES"), new IvParameterSpec(IV));

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            String message = "Hello, World!";

            // Encrypt message for participant 1
            String encryptedMessage1 = encrypt(message, "Participant1");
            System.out.println("Encrypted Message for Participant 1: " + encryptedMessage1);

            // Encrypt message for participant 2
            String encryptedMessage2 = encrypt(message, "Participant2");
            System.out.println("Encrypted Message for Participant 2: " + encryptedMessage2);

            // Encrypt message for participant 3
            String encryptedMessage3 = encrypt(message, "Participant3");
            System.out.println("Encrypted Message for Participant 3: " + encryptedMessage3);

            // Decrypt messages for each participant
            String decryptedMessage1 = decrypt(encryptedMessage1, "Participant1");
            System.out.println("Decrypted Message for Participant 1: " + decryptedMessage1);

            String decryptedMessage2 = decrypt(encryptedMessage2, "Participant2");
            System.out.println("Decrypted Message for Participant 2: " + decryptedMessage2);

            String decryptedMessage3 = decrypt(encryptedMessage3, "Participant3");
            System.out.println("Decrypted Message for Participant 3: " + decryptedMessage3);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}