import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCFB1 {

    private static final String AES_KEY = "0123456789abcdef"; // 16 bytes key
    private static final String IV1 = "1234567890abcdef"; // 16 bytes IV for participant 1
    private static final String IV2 = "2345678901abcdef"; // 16 bytes IV for participant 2
    private static final String IV3 = "3456789012abcdef"; // 16 bytes IV for participant 3

    public static String encrypt(String text, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(AES_KEY.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(text.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String text, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(AES_KEY.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(text));
        return new String(decrypted);
    }

    public static void main(String[] args) throws Exception {
        // Participant 1 sending a message
        String message1 = "Hello from participant 1!";
        String encryptedMessage1 = encrypt(message1, IV1);
        System.out.println("Encrypted message from participant 1: " + encryptedMessage1);

        // Participant 2 receiving and decrypting the message
        String decryptedMessage1 = decrypt(encryptedMessage1, IV1);
        System.out.println("Decrypted message for participant 2: " + decryptedMessage1);

        // Participant 3 sending a message
        String message2 = "Greetings from participant 3!";
        String encryptedMessage2 = encrypt(message2, IV3);
        System.out.println("Encrypted message from participant 3: " + encryptedMessage2);

        // Participant 1 receiving and decrypting the message
        String decryptedMessage2 = decrypt(encryptedMessage2, IV3);
        System.out.println("Decrypted message for participant 1: " + decryptedMessage2);
    }
}