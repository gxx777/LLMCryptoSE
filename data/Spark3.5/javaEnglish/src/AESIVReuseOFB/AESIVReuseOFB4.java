import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseOFB4 {
    private static final String ALGORITHM = "AES/OFB/NoPadding";
    private static final String KEY = "abcdefghijklmnop"; // 16 chars = 128 bit
    private static final String IV = "1234567890abcdef"; // 16 chars = 128 bit

    public String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV.getBytes(StandardCharsets.UTF_8));
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public void sendMessageToParticipant1(String message) throws Exception {
        String encryptedMessage = encrypt(message);
        // Send encryptedMessage to participant1
    }

    public void sendMessageToParticipant2(String message) throws Exception {
        String encryptedMessage = encrypt(message);
        // Send encryptedMessage to participant2
    }

    public void sendMessageToParticipant3(String message) throws Exception {
        String encryptedMessage = encrypt(message);
        // Send encryptedMessage to participant3
    }
}