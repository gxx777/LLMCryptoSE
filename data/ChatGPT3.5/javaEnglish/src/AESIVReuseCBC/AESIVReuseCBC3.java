import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCBC3 {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    
    private static final String key = "SecretKey1234567"; // 16-byte key for AES encryption
    private static final String iv = "RandomIV8888888"; // 16-byte initialization vector for AES encryption

    public static void sendMessage(String message, String participant) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

            byte[] encryptedMessage = cipher.doFinal(message.getBytes());
            String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessage);

            System.out.println("Sending encrypted message to " + participant + ": " + encodedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        String message1 = "Hello, Participant 1!";
        String message2 = "Greetings, Participant 2!";
        String message3 = "Hi there, Participant 3!";

        sendMessage(message1, "Participant 1");
        sendMessage(message2, "Participant 2");
        sendMessage(message3, "Participant 3");
    }
}