import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCFB1 {
    private static final String ALGORITHM = "AES/CFB/NoPadding";
    private static final String KEY = "abcdefghijklmnop"; // 16 bytes key for AES-128
    private static final String INIT_VECTOR = "qrstuvwxyzabcdef"; // 16 bytes IV

    public static void main(String[] args) throws Exception {
        String message1 = "Hello, participant 1!";
        String message2 = "Hello, participant 2!";
        String message3 = "Hello, participant 3!";

        byte[] encryptedMessage1 = encrypt(message1);
        byte[] encryptedMessage2 = encrypt(message2);
        byte[] encryptedMessage3 = encrypt(message3);

        System.out.println("Encrypted message for participant 1: " + Base64.getEncoder().encodeToString(encryptedMessage1));
        System.out.println("Encrypted message for participant 2: " + Base64.getEncoder().encodeToString(encryptedMessage2));
        System.out.println("Encrypted message for participant 3: " + Base64.getEncoder().encodeToString(encryptedMessage3));
    }

    private static byte[] encrypt(String message) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(INIT_VECTOR.getBytes(StandardCharsets.UTF_8));

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        return cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
    }
}