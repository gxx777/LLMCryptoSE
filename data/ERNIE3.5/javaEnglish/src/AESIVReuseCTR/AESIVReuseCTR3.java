import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCTR3 {

    private static final String KEY = "0123456789abcdef"; // 16-byte key
    private static final String IV = "abcdef0123456789"; // 16-byte IV

    public static void main(String[] args) throws Exception {
        String[] messages = {
                "Message to Participant 1",
                "Message to Participant 2",
                "Message to Participant 3"
        };

        String[] recipients = {
                "Participant1",
                "Participant2",
                "Participant3"
        };

        for (int i = 0; i < messages.length; i++) {
            String encryptedMessage = encryptCTR(messages[i], KEY, IV);
            System.out.println("Sending encrypted message to " + recipients[i] + ": " + encryptedMessage);
        }
    }

    private static String encryptCTR(String message, String key, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}