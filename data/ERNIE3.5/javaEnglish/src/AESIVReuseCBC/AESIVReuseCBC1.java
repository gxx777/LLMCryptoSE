import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCBC1 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final byte[] KEY = "MySecretKey".getBytes(StandardCharsets.UTF_8); // Replace with your own key
    private static final byte[] IV = "MyInitializationVector".getBytes(StandardCharsets.UTF_8); // Replace with your own IV

    public static String encrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"), new IvParameterSpec(IV));

        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(KEY, "AES"), new IvParameterSpec(IV));

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        String message1 = "Hello, Participant 1!";
        String encryptedMessage1 = encrypt(message1);
        String decryptedMessage1 = decrypt(encryptedMessage1);
        System.out.println("Message 1: Original - " + message1 + ", Encrypted - " + encryptedMessage1 + ", Decrypted - " + decryptedMessage1);

        String message2 = "Hello, Participant 2!";
        String encryptedMessage2 = encrypt(message2);
        String decryptedMessage2 = decrypt(encryptedMessage2);
        System.out.println("Message 2: Original - " + message2 + ", Encrypted - " + encryptedMessage2 + ", Decrypted - " + decryptedMessage2);

        String message3 = "Hello, Participant 3!";
        String encryptedMessage3 = encrypt(message3);
        String decryptedMessage3 = decrypt(encryptedMessage3);
        System.out.println("Message 3: Original - " + message3 + ", Encrypted - " + encryptedMessage3 + ", Decrypted - " + decryptedMessage3);
    }
}