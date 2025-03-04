import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCFB2 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CFB/PKCS5Padding"; // Cipher Feedback Mode with PKCS5Padding
    private static final String CHARSET = "UTF-8";

    private static final String SECRET_KEY = "MySuperSecretKey"; // 16 bytes secret key
    private static final String IV = "MyIVVector123456"; // 16 bytes initialization vector

    public static String encrypt(String input) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(CHARSET), ALGORITHM);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes(CHARSET));

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            byte[] encryptedBytes = cipher.doFinal(input.getBytes(CHARSET));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String input) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(CHARSET), ALGORITHM);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes(CHARSET));

            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(input));
            return new String(decryptedBytes, CHARSET);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        String message1 = "Hello, Participant 1!";
        String message2 = "Greetings, Participant 2!";
        String message3 = "Good day, Participant 3!";

        String encryptedMessage1 = encrypt(message1);
        String encryptedMessage2 = encrypt(message2);
        String encryptedMessage3 = encrypt(message3);

        System.out.println("Encrypted Message 1: " + encryptedMessage1);
        System.out.println("Encrypted Message 2: " + encryptedMessage2);
        System.out.println("Encrypted Message 3: " + encryptedMessage3);

        System.out.println("Decrypted Message 1: " + decrypt(encryptedMessage1));
        System.out.println("Decrypted Message 2: " + decrypt(encryptedMessage2));
        System.out.println("Decrypted Message 3: " + decrypt(encryptedMessage3));
    }
}