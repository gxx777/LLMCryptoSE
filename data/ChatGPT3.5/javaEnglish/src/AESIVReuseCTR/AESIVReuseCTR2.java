import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR2 {

    private static final String AES_MODE = "AES/CTR/NoPadding";
    private static final String CHARSET = "UTF-8";

    private static final String participant1Key = "SecretKey1";
    private static final String participant2Key = "SecretKey2";
    private static final String participant3Key = "SecretKey3";

    private static final String participant1 = "Participant1";
    private static final String participant2 = "Participant2";
    private static final String participant3 = "Participant3";

    public static void main(String[] args) throws Exception {
        String message = "Hello participants!";

        sendSecureMessage(participant1, participant1Key, message);
        sendSecureMessage(participant2, participant2Key, message);
        sendSecureMessage(participant3, participant3Key, message);
    }

    private static void sendSecureMessage(String participant, String key, String message) throws Exception {
        byte[] keyBytes = key.getBytes(CHARSET);
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        Key secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance(AES_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

        byte[] encryptedMessage = cipher.doFinal(message.getBytes(CHARSET));
        String encryptedMessageBase64 = Base64.getEncoder().encodeToString(encryptedMessage);

        System.out.println("Secure message sent to " + participant + ": " + encryptedMessageBase64);
    }
}