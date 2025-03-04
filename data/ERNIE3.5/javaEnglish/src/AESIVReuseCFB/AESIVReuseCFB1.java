import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCFB1 {

    private static final String KEY = "ThisIsASecretKey"; // Replace with a strong key
    private static final String IV = "ThisIsAnIV"; // Replace with a unique IV for each encryption

    public static void main(String[] args) throws Exception {
        String[] participants = {"Participant1", "Participant2", "Participant3"};
        String[] messages = {"Hello P1", "Hello P2", "Hello P3"};

        for (int i = 0; i < participants.length; i++) {
            String encryptedMessage = encryptMessage(messages[i]);
            System.out.println("Sending encrypted message to " + participants[i] + ": " + encryptedMessage);
        }
    }

    private static String encryptMessage(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes(StandardCharsets.UTF_8));

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}