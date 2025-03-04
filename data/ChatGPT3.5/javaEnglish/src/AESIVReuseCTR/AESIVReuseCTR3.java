import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCTR3 {
    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final String SECRET_KEY = "secretkey1234567";
    private static final String IV = "initialvector123";

    public static void sendMessage(String message, String participant) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes());

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            byte[] encryptedMessage = cipher.doFinal(message.getBytes());
            String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessage);

            System.out.println("Sending message to " + participant + ": " + encodedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        sendMessage("Hello participant1", "participant1");
        sendMessage("Hello participant2", "participant2");
        sendMessage("Hello participant3", "participant3");
    }
}