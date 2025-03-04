import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESKeyReuse4 {
    private static final String SECRET_KEY = "my-secret-key-123"; // 16 characters

    public static void main(String[] args) throws Exception {
        String message = "Hello, World!";
        System.out.println("Original Message : " + message);

        String encryptedMessage1 = encrypt(message, SECRET_KEY);
        System.out.println("Encrypted Message 1 : " + encryptedMessage1);

        String encryptedMessage2 = encrypt(message, SECRET_KEY);
        System.out.println("Encrypted Message 2 : " + encryptedMessage2);

        String encryptedMessage3 = encrypt(message, SECRET_KEY);
        System.out.println("Encrypted Message 3 : " + encryptedMessage3);
    }

    public static String encrypt(String strToEncrypt, String secret) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(secret.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }
}