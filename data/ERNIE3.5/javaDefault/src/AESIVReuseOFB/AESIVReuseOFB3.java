import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseOFB3 {

    private static final String AES = "AES";
    private static final String OFB = "OFB";
    private static final String SECRET_KEY = "ThisIsASecretKey"; // 16 bytes key for AES

    // Encrypts the message using the same IV for each encryption.
    // This is NOT SECURE in practice.
    public static String encrypt(String message, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES + "/" + OFB + "/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), AES);
        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // Decrypts the message using the same IV that was used for encryption.
    // This is NOT SECURE in practice.
    public static String decrypt(String encryptedMessage, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES + "/" + OFB + "/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), AES);
        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decoded = Base64.getDecoder().decode(encryptedMessage);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        // Example usage:
        String message1 = "Hello, World!";
        String message2 = "This is a secret message.";
        String message3 = "Goodbye, everyone.";

        // Reusing the same IV for all messages. This is NOT SECURE!
        String iv = "1234567890123456"; // This IV should be unique for each encryption

        String encrypted1 = encrypt(message1, iv);
        String encrypted2 = encrypt(message2, iv);
        String encrypted3 = encrypt(message3, iv);

        System.out.println("Encrypted Message 1: " + encrypted1);
        System.out.println("Encrypted Message 2: " + encrypted2);
        System.out.println("Encrypted Message 3: " + encrypted3);

        // Decrypting the messages with the same IV
        String decrypted1 = decrypt(encrypted1, iv);
        String decrypted2 = decrypt(encrypted2, iv);
        String decrypted3 = decrypt(encrypted3, iv);

        System.out.println("Decrypted Message 1: " + decrypted1);
        System.out.println("Decrypted Message 2: " + decrypted2);
        System.out.println("Decrypted Message 3: " + decrypted3);
    }
}