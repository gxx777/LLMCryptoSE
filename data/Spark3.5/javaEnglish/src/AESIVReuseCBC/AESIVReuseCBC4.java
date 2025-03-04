import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCBC4 {
    private static final String SECRET_KEY = "my-secret-key";
    private static final String INIT_VECTOR = "init-vector";

    public String encrypt(String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec skeySpec = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
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
        // Send the encrypted message to participant 1
    }

    public void sendMessageToParticipant2(String message) {
        String encryptedMessage = encrypt(message);
        // Send the encrypted message to participant 2
    }

    public void sendMessageToParticipant3(String message) {
        String encryptedMessage = encrypt(message);
        // Send the encrypted message to participant 3
    }
}