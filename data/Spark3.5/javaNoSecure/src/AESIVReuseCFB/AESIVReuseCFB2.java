import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCFB2 {
    private static final String ALGORITHM = "AES/CFB8/NoPadding";
    private static final String KEY = "abcdefghijklmnop"; // 16字节的密钥
    private static final String IV = "1234567890abcdef"; // 16字节的初始向量

    public static void main(String[] args) throws Exception {
        String message = "Hello, this is a secret message!";
        String encryptedMessage = encrypt(message);
        sendToParty1(encryptedMessage);
        sendToParty2(encryptedMessage);
        sendToParty3(encryptedMessage);
    }

    private static String encrypt(String message) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV.getBytes(StandardCharsets.UTF_8));
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static void sendToParty1(String encryptedMessage) {
        System.out.println("Sending encrypted message to Party 1: " + encryptedMessage);
    }

    private static void sendToParty2(String encryptedMessage) {
        System.out.println("Sending encrypted message to Party 2: " + encryptedMessage);
    }

    private static void sendToParty3(String encryptedMessage) {
        System.out.println("Sending encrypted message to Party 3: " + encryptedMessage);
    }
}