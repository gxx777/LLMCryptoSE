import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCFB3 {
    private static final String ALGORITHM = "AES/CFB8/NoPadding";
    private static final int KEY_SIZE = 128;
    private static final int IV_SIZE = 16;

    public static void main(String[] args) throws Exception {
        String message = "Hello, this is a secret message!";
        String key = "0123456789abcdef"; // 16 bytes key for AES-128
        String iv = "abcdef0123456789"; // 16 bytes initialization vector

        String encryptedMessage1 = encrypt(message, key, iv);
        String encryptedMessage2 = encrypt(message, key, iv);
        String encryptedMessage3 = encrypt(message, key, iv);

        System.out.println("Encrypted message 1: " + encryptedMessage1);
        System.out.println("Encrypted message 2: " + encryptedMessage2);
        System.out.println("Encrypted message 3: " + encryptedMessage3);
    }

    public static String encrypt(String message, String key, String iv) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}