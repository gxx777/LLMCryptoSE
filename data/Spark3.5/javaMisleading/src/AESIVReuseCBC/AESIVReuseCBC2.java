import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCBC2 {
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String KEY = "abcdefghijklmnop"; // 16字节的密钥
    private static final String IV = "1234567890abcdef"; // 16字节的初始向量

    public static void main(String[] args) throws Exception {
        String message1 = "Alice: Hi, Bob!";
        String message2 = "Bob: Hi, Alice!";
        String message3 = "Charlie: Hi, Alice and Bob!";

        String encryptedMessage1 = encrypt(message1);
        String encryptedMessage2 = encrypt(message2);
        String encryptedMessage3 = encrypt(message3);

        System.out.println("Encrypted messages:");
        System.out.println("Message 1: " + encryptedMessage1);
        System.out.println("Message 2: " + encryptedMessage2);
        System.out.println("Message 3: " + encryptedMessage3);
    }

    public static String encrypt(String message) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV.getBytes(StandardCharsets.UTF_8));

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}