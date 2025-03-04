import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseOFB1 {

    private static final String ALGORITHM = "AES/OFB/NoPadding";
    private static final byte[] KEY = "MySecretKey1234567890123456".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV = "MyInitializationVector".getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) throws Exception {
        String message1 = "Message for Participant 1";
        String message2 = "Message for Participant 2";
        String message3 = "Message for Participant 3";

        String encryptedMessage1 = encrypt(message1);
        String encryptedMessage2 = encrypt(message2);
        String encryptedMessage3 = encrypt(message3);

        System.out.println("Encrypted Message 1: " + encryptedMessage1);
        System.out.println("Encrypted Message 2: " + encryptedMessage2);
        System.out.println("Encrypted Message 3: " + encryptedMessage3);
    }

    public static String encrypt(String message) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }
}