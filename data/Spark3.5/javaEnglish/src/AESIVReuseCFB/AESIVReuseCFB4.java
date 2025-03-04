import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCFB4 {
    private static final String ALGORITHM = "AES/CFB4Padding";
    private static final String KEY = "abcdefghijklmnop"; // 16 chars = 128 bit
    private static final String INIT_VECTOR = "randominitvector"; // 16 chars = 128 bit

    public String encrypt(String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec skeySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public void sendMessageToParticipant1(String message) {
        String encryptedMessage = encrypt(message);
        // Send encryptedMessage to participant1
    }

    public void sendMessageToParticipant2(String message) {
        String encryptedMessage = encrypt(message);
        // Send encryptedMessage to participant2
    }

    public void sendMessageToParticipant3(String message) {
        String encryptedMessage = encrypt(message);
        // Send encryptedMessage to participant3
    }
}