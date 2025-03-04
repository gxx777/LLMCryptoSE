import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCBC3 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final byte[] KEY = "Your256bitSecretKeyHere".getBytes(StandardCharsets.UTF_8); // 256-bit key
    private static final byte[] IV = "Your16ByteInitializationVector".getBytes(StandardCharsets.UTF_8); // 16-byte IV

    public static void main(String[] args) throws Exception {
        String[] messages = {"Message 1", "Message 2", "Message 3"};
        String[] recipients = {"Recipient 1", "Recipient 2", "Recipient 3"};

        for (int i = 0; i < messages.length; i++) {
            String encryptedMessage = encrypt(messages[i]);
            System.out.println("Sending encrypted message to " + recipients[i] + ": " + encryptedMessage);
        }
    }

    public static String encrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}