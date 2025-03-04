import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCTR2 {
    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final byte[] KEY = "ThisIsASecretKey1234567890".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV = "ThisIsAnIV1234567890".getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) throws Exception {
        String message1 = "Message for Participant 1";
        String message2 = "Message for Participant 2";
        String message3 = "Message for Participant 3";

        String encryptedMessage1 = encryptMessage(message1);
        String encryptedMessage2 = encryptMessage(message2);
        String encryptedMessage3 = encryptMessage(message3);

        System.out.println("Encrypted message for Participant 1: " + encryptedMessage1);
        System.out.println("Encrypted message for Participant 2: " + encryptedMessage2);
        System.out.println("Encrypted message for Participant 3: " + encryptedMessage3);
    }

    private static String encryptMessage(String message) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}