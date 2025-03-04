import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCBC3 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final byte[] KEY = "MySecretKey".getBytes(StandardCharsets.UTF_8); // Replace with your own key
    private static final byte[] IV = "MyInitializationVector".getBytes(StandardCharsets.UTF_8); // Replace with your own IV

    public static void main(String[] args) throws Exception {
        String[] participants = {"Participant1", "Participant2", "Participant3"};
        String[] messages = {"Hello Participant 1", "Hello Participant 2", "Hello Participant 3"};

        for (int i = 0; i < participants.length; i++) {
            String encryptedMessage = encryptMessage(messages[i]);
            System.out.println("Sending encrypted message to " + participants[i] + ": " + encryptedMessage);
        }
    }

    private static String encryptMessage(String message) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}