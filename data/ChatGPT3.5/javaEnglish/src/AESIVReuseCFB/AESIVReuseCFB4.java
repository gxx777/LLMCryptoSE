import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCFB4 {

    private static final String AES_ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CFB/PKCS5Padding";

    private static final String participant1Key = "secretKey1";
    private static final String participant2Key = "secretKey2";
    private static final String participant3Key = "secretKey3";

    public static String sendMessage(String message, String key) throws Exception {
        byte[] keyBytes = key.getBytes();
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, AES_ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[cipher.getBlockSize()]));
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedMessage);
    }

    public static void main(String[] args) throws Exception {
        String message = "Hello, participant 1, 2, and 3!";
        String encryptedMessage1 = sendMessage(message, participant1Key);
        String encryptedMessage2 = sendMessage(message, participant2Key);
        String encryptedMessage3 = sendMessage(message, participant3Key);

        System.out.println("Encrypted message for participant 1: " + encryptedMessage1);
        System.out.println("Encrypted message for participant 2: " + encryptedMessage2);
        System.out.println("Encrypted message for participant 3: " + encryptedMessage3);
    }
}