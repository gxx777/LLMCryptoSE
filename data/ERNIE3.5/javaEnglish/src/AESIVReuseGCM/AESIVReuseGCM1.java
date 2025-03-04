import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESIVReuseGCM1 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final byte[] KEY = "ThisIsASecretKey1234567890".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV = "ThisIsAnIV1234567890".getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) {
        String[] messages = {"Message1", "Message2", "Message3"};
        String[] recipients = {"Recipient1", "Recipient2", "Recipient3"};

        for (int i = 0; i < messages.length; i++) {
            try {
                String encryptedMessage = encryptMessage(messages[i]);
                System.out.println("Sending encrypted message to " + recipients[i] + ": " + encryptedMessage);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static String encryptMessage(String message) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, IV);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
        byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(encrypted);
    }
}