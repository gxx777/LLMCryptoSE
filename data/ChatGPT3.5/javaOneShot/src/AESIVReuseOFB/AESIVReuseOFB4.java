import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseOFB4 {

    private static final String key1 = "abcdefghijklmnop";
    private static final String key2 = "qrstuvwxyz123456";
    private static final String key3 = "9876543210abcdef";

    private static final String IV = "1234567890abcdef";

    public static String encryptMessage(String message, String key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        IvParameterSpec iv = new IvParameterSpec(IV.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        byte[] encrypted = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decryptMessage(String encryptedMessage, String key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        IvParameterSpec iv = new IvParameterSpec(IV.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decrypted);
    }

    public static void main(String[] args) throws Exception {
        String message1 = "Hello from Participant 1";
        String message2 = "Hello from Participant 2";
        String message3 = "Hello from Participant 3";

        String encryptedMessage1 = encryptMessage(message1, key1);
        String encryptedMessage2 = encryptMessage(message2, key2);
        String encryptedMessage3 = encryptMessage(message3, key3);

        System.out.println("Encrypted message 1: " + encryptedMessage1);
        System.out.println("Encrypted message 2: " + encryptedMessage2);
        System.out.println("Encrypted message 3: " + encryptedMessage3);

        String decryptedMessage1 = decryptMessage(encryptedMessage1, key1);
        String decryptedMessage2 = decryptMessage(encryptedMessage2, key2);
        String decryptedMessage3 = decryptMessage(encryptedMessage3, key3);

        System.out.println("Decrypted message 1: " + decryptedMessage1);
        System.out.println("Decrypted message 2: " + decryptedMessage2);
        System.out.println("Decrypted message 3: " + decryptedMessage3);
    }
}