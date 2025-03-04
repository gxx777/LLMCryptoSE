import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseOFB2 {

    private static final String key1 = "randomkey1234567"; // 32 bytes key
    private static final String key2 = "anotherkey7654321"; // 32 bytes key
    private static final String key3 = "secretkeyabcdefg"; // 32 bytes key

    private static final String IV1 = "randomiv12345678"; // 16 bytes IV
    private static final String IV2 = "anotheriv87654321"; // 16 bytes IV
    private static final String IV3 = "secretivabcdefgh"; // 16 bytes IV

    public static String encrypt(String plainText, String key, String IV) {
        try {
            Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(IV.getBytes()));
            byte[] encryptedText = cipher.doFinal(plainText.getBytes());
            return Base64.getEncoder().encodeToString(encryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String encryptedText, String key, String IV) {
        try {
            Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(IV.getBytes()));
            byte[] decryptedText = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
            return new String(decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        String message1 = "Hello from participant 1!";
        String message2 = "Hello from participant 2!";
        String message3 = "Hello from participant 3!";

        // Encrypt and send messages to each participant
        String encryptedMessage1 = encrypt(message1, key1, IV1);
        String encryptedMessage2 = encrypt(message2, key2, IV2);
        String encryptedMessage3 = encrypt(message3, key3, IV3);

        // Decrypt messages received from each participant
        String decryptedMessage1 = decrypt(encryptedMessage1, key1, IV1);
        String decryptedMessage2 = decrypt(encryptedMessage2, key2, IV2);
        String decryptedMessage3 = decrypt(encryptedMessage3, key3, IV3);

        System.out.println("Participant 1 received: " + decryptedMessage1);
        System.out.println("Participant 2 received: " + decryptedMessage2);
        System.out.println("Participant 3 received: " + decryptedMessage3);
    }
}