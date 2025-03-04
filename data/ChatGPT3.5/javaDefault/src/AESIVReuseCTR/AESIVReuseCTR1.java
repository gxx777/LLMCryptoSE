import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;

public class AESIVReuseCTR1 {

    private static final String AES_ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CTR/NoPadding";

    private static final byte[] IV = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    private static final String KEY1 = "abcdefghijklmnop"; // 16 bytes key for participant 1
    private static final String KEY2 = "bcdefghijklmnopq"; // 16 bytes key for participant 2
    private static final String KEY3 = "cdefghijklmnopqr"; // 16 bytes key for participant 3

    public static String encryptMessage(String message, String key) throws Exception {
        Key secretKey = new SecretKeySpec(key.getBytes(), AES_ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(IV));
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decryptMessage(String encryptedMessage, String key) throws Exception {
        Key secretKey = new SecretKeySpec(key.getBytes(), AES_ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(IV));
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        String message1 = "Hello from participant 1";
        String message2 = "Hello from participant 2";
        String message3 = "Hello from participant 3";

        String encryptedMessage1 = encryptMessage(message1, KEY1);
        String encryptedMessage2 = encryptMessage(message2, KEY2);
        String encryptedMessage3 = encryptMessage(message3, KEY3);

        System.out.println("Encrypted message from participant 1: " + encryptedMessage1);
        System.out.println("Encrypted message from participant 2: " + encryptedMessage2);
        System.out.println("Encrypted message from participant 3: " + encryptedMessage3);

        String decryptedMessage1 = decryptMessage(encryptedMessage1, KEY1);
        String decryptedMessage2 = decryptMessage(encryptedMessage2, KEY2);
        String decryptedMessage3 = decryptMessage(encryptedMessage3, KEY3);

        System.out.println("Decrypted message from participant 1: " + decryptedMessage1);
        System.out.println("Decrypted message from participant 2: " + decryptedMessage2);
        System.out.println("Decrypted message from participant 3: " + decryptedMessage3);
    }
}