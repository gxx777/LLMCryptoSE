import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseOFB4 {
    private static final String ALGORITHM = "AES/OFB/NoPadding";
    private static final byte[] KEY = "ThisIsASecretKey".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV = "ThisIsAnIV".getBytes(StandardCharsets.UTF_8);

    public static String encryptMessage(String message, String recipient) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        String encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes);
        return "To " + recipient + ": " + encryptedMessage;
    }

    public static String decryptMessage(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage.split(": ")[1]));

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        String message1 = "Hello, Alice!";
        String message2 = "Hello, Bob!";
        String message3 = "Hello, Charlie!";

        String encryptedMessage1 = encryptMessage(message1, "Alice");
        String encryptedMessage2 = encryptMessage(message2, "Bob");
        String encryptedMessage3 = encryptMessage(message3, "Charlie");

        System.out.println("Encrypted message for Alice: " + encryptedMessage1);
        System.out.println("Encrypted message for Bob: " + encryptedMessage2);
        System.out.println("Encrypted message for Charlie: " + encryptedMessage3);

        String decryptedMessage1 = decryptMessage(encryptedMessage1);
        String decryptedMessage2 = decryptMessage(encryptedMessage2);
        String decryptedMessage3 = decryptMessage(encryptedMessage3);

        System.out.println("Decrypted message for Alice: " + decryptedMessage1);
        System.out.println("Decrypted message for Bob: " + decryptedMessage2);
        System.out.println("Decrypted message for Charlie: " + decryptedMessage3);
    }
}