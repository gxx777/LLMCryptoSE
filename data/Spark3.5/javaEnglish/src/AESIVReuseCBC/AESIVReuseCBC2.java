import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCBC2 {
    private static final String SECRET_KEY = "my-secret-key";
    private static final String INIT_VECTOR = "init-vector";

    public static void main(String[] args) {
        String message = "Hello, World!";
        sendMessage(message, "Participant1");
        sendMessage(message, "Participant2");
        sendMessage(message, "Participant3");
    }

    public static void sendMessage(String message, String participant) {
        try {
            IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec skeySpec = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(message.getBytes());
            String encoded = Base64.getEncoder().encodeToString(encrypted);

            System.out.println("Sending encrypted message to " + participant + ": " + encoded);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}