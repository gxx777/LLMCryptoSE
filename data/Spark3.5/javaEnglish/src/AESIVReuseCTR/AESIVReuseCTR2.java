import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCTR2 {
    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final String KEY = "abcdefghijklmnop"; // 16 chars = 128 bit key
    private static final String IV = "1234567890abcdef"; // 16 chars = 128 bit IV

    public void sendMessage(String message, String participant) throws Exception {
        byte[] ivBytes = IV.getBytes(StandardCharsets.UTF_8);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        byte[] keyBytes = KEY.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec skeySpec = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        byte[] encrypted = cipher.doFinal(message.getBytes());
        String encryptedText = Base64.getEncoder().encodeToString(encrypted);

        System.out.println("Sending encrypted message to " + participant + ": " + encryptedText);
    }

    public static void main(String[] args) throws Exception {
        AESIVReuseCTR2 aes = new AESIVReuseCTR2();
        aes.sendMessage("Hello, participant 1!", "Participant 1");
        aes.sendMessage("Hello, participant 2!", "Participant 2");
        aes.sendMessage("Hello, participant 3!", "Participant 3");
    }
}