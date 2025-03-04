import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;

public class AESIVReuseCBC1 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final byte[] KEY = "ThisIsASecretKeyThisIsASecretKey".getBytes(StandardCharsets.UTF_8); // 256-bit key
    private static final byte[] IV = "ThisIsAnInitializationVector".getBytes(StandardCharsets.UTF_8); // 16-byte IV

    public static String encrypt(String valueToEncrypt) throws Exception {
        Key key = new SecretKeySpec(KEY, "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encryptedValue = cipher.doFinal(valueToEncrypt.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(encryptedValue);
    }

    public static String decrypt(String encryptedValue) throws Exception {
        Key key = new SecretKeySpec(KEY, "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] originalValue = cipher.doFinal(Base64.getDecoder().decode(encryptedValue));

        return new String(originalValue, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            String originalMessage = "Hello, World!";

            // Encrypt the message
            String encryptedMessage = encrypt(originalMessage);
            System.out.println("Encrypted: " + encryptedMessage);

            // Decrypt the message
            String decryptedMessage = decrypt(encryptedMessage);
            System.out.println("Decrypted: " + decryptedMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}