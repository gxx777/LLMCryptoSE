import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;

public class AESKeyReuse1 {
    private static final String AES_ALGORITHM = "AES";
    private static final String AES_KEY = "1234567890123456"; // 16 bytes key for AES encryption

    public static String encryptMessage(String message, String key) {
        try {
            Key aesKey = new SecretKeySpec(key.getBytes(), AES_ALGORITHM);
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encrypted = cipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decryptMessage(String encryptedMessage, String key) {
        try {
            Key aesKey = new SecretKeySpec(key.getBytes(), AES_ALGORITHM);
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] encrypted = Base64.getDecoder().decode(encryptedMessage);
            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        String message1 = "Hello, participant 1!";
        String message2 = "Greetings to participant 2!";
        String message3 = "Welcome from participant 3!";

        String encryptedMessage1 = encryptMessage(message1, AES_KEY);
        String encryptedMessage2 = encryptMessage(message2, AES_KEY);
        String encryptedMessage3 = encryptMessage(message3, AES_KEY);

        System.out.println("Encrypted message 1: " + encryptedMessage1);
        System.out.println("Decrypted message 1: " + decryptMessage(encryptedMessage1, AES_KEY));

        System.out.println("Encrypted message 2: " + encryptedMessage2);
        System.out.println("Decrypted message 2: " + decryptMessage(encryptedMessage2, AES_KEY));

        System.out.println("Encrypted message 3: " + encryptedMessage3);
        System.out.println("Decrypted message 3: " + decryptMessage(encryptedMessage3, AES_KEY));
    }
}