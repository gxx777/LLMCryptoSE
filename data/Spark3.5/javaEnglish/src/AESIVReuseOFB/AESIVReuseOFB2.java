import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseOFB2 {
    private static final String ALGORITHM = "AES/OFB/NoPadding";
    private static final String KEY = "abcdefghijklmnop"; // 16 chars = 128 bit
    private static final String IV = "1234567890abcdef"; // 16 chars = 128 bit

    public static void main(String[] args) throws Exception {
        String message = "Hello, World!";
        System.out.println("Original Message: " + message);

        String encryptedMessage1 = encrypt(message, "Participant1");
        String encryptedMessage2 = encrypt(message, "Participant2");
        String encryptedMessage3 = encrypt(message, "Participant3");

        System.out.println("Encrypted Message for Participant1: " + encryptedMessage1);
        System.out.println("Encrypted Message for Participant2: " + encryptedMessage2);
        System.out.println("Encrypted Message for Participant3: " + encryptedMessage3);
    }

    private static String encrypt(String message, String participant) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV.getBytes(StandardCharsets.UTF_8));
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }
}