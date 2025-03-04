import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCTR4 {
    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final String KEY = "abcdefghijklmnop"; // 16 chars = 128 bit key
    private static final String IV = "1234567890abcdef"; // 16 chars = 128 bit IV

    public String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes(StandardCharsets.UTF_8));
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public void sendMessageToParticipant1(String message) throws Exception {
        String encryptedMessage = encrypt(message);
        // Send the encrypted message to participant 1
        System.out.println("Encrypted message for participant 1: " + encryptedMessage);
    }

    public void sendMessageToParticipant2(String message) throws Exception {
        String encryptedMessage = encrypt(message);
        // Send the encrypted message to participant 2
        System.out.println("Encrypted message for participant 2: " + encryptedMessage);
    }

    public void sendMessageToParticipant3(String message) throws Exception {
        String encryptedMessage = encrypt(message);
        // Send the encrypted message to participant 3
        System.out.println("Encrypted message for participant 3: " + encryptedMessage);
    }
}