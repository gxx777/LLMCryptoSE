import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCBC1 {
    private static final String KEY = "abcdefghijklmnop"; // 16 bytes key for AES-128
    private static final String INIT_VECTOR = "abcdefghijklmnop"; // 16 bytes IV for AES-CBC

    public static void main(String[] args) {
        String message1 = "Hello, participant 1!";
        String message2 = "Hello, participant 2!";
        String message3 = "Hello, participant 3!";

        try {
            String encryptedMessage1 = encrypt(message1);
            String encryptedMessage2 = encrypt(message2);
            String encryptedMessage3 = encrypt(message3);

            System.out.println("Encrypted message for participant 1: " + encryptedMessage1);
            System.out.println("Encrypted message for participant 2: " + encryptedMessage2);
            System.out.println("Encrypted message for participant 3: " + encryptedMessage3);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String encrypt(String value) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec skeySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        byte[] encrypted = cipher.doFinal(value.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
}