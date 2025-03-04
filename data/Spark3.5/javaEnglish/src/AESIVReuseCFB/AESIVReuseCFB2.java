import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCFB2 {
    private static final String ALGORITHM = "AES/CFB8/NoPadding";
    private static final String KEY = "abcdefghijklmnop"; // 16 chars = 128 bit
    private static final String INIT_VECTOR = "randominitvector"; // 16 chars = 128 bit

    public static void main(String[] args) throws Exception {
        String message = "Hello, World!";
        System.out.println("Original Message : " + message);

        String encryptedMessage1 = encrypt(message, "participant1");
        String encryptedMessage2 = encrypt(message, "participant2");
        String encryptedMessage3 = encrypt(message, "participant3");

        System.out.println("Encrypted Message for participant1 : " + encryptedMessage1);
        System.out.println("Encrypted Message for participant2 : " + encryptedMessage2);
        System.out.println("Encrypted Message for participant3 : " + encryptedMessage3);
    }

    public static String encrypt(String value, String participant) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec skeySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        byte[] encrypted = cipher.doFinal(value.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
}