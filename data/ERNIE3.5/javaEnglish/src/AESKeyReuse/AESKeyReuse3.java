import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESKeyReuse3 {
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final byte[] ENCRYPTION_KEY = "ThisIsASecretKey".getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) throws Exception {
        String message1 = "Message for Participant 1";
        String message2 = "Message for Participant 2";
        String message3 = "Message for Participant 3";

        String encryptedMessage1 = encryptMessage(message1);
        String encryptedMessage2 = encryptMessage(message2);
        String encryptedMessage3 = encryptMessage(message3);

        System.out.println("Encrypted Message for Participant 1: " + encryptedMessage1);
        System.out.println("Encrypted Message for Participant 2: " + encryptedMessage2);
        System.out.println("Encrypted Message for Participant 3: " + encryptedMessage3);
    }

    public static String encryptMessage(String message) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY, ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}