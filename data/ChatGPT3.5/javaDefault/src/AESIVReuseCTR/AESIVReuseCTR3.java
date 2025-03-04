import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR3 {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "CTR";
    private static final String PADDING = "NoPadding";
    private static final int KEY_SIZE = 16;

    public static void main(String[] args) {
        String key = "secretkey1234567"; // 16 bytes key
        String iv = generateIV();

        // Participant 1
        String message1 = "Hello Participant 2!";
        String encryptedMessage1 = encryptMessage(key, iv, message1);
        System.out.println("Participant 1 sends: " + encryptedMessage1);

        // Participant 2
        String message2 = "Hello Participant 3!";
        String encryptedMessage2 = encryptMessage(key, iv, message2);
        System.out.println("Participant 2 sends: " + encryptedMessage2);

        // Participant 3
        String message3 = "Hello Participant 1!";
        String encryptedMessage3 = encryptMessage(key, iv, message3);
        System.out.println("Participant 3 sends: " + encryptedMessage3);
    }

    private static String encryptMessage(String key, String iv, String message) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), ALGORITHM);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            byte[] encryptedBytes = cipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    private static String generateIV() {
        byte[] iv = new byte[KEY_SIZE];
        new SecureRandom().nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
    }
}