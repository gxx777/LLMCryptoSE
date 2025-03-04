import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCBC3 {
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String KEY = "abcdefghijklmnop"; // 16 bytes key for AES-128
    private static final String IV = "1234567890abcdef"; // 16 bytes initialization vector

    public static void main(String[] args) {
        String message = "Hello, this is a secret message!";
        try {
            byte[] encryptedMessage1 = encrypt(message);
            byte[] encryptedMessage2 = encrypt(message);
            byte[] encryptedMessage3 = encrypt(message);

            System.out.println("Encrypted message 1: " + Base64.getEncoder().encodeToString(encryptedMessage1));
            System.out.println("Encrypted message 2: " + Base64.getEncoder().encodeToString(encryptedMessage2));
            System.out.println("Encrypted message 3: " + Base64.getEncoder().encodeToString(encryptedMessage3));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] encrypt(String message) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV.getBytes(StandardCharsets.UTF_8));

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        return cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
    }
}