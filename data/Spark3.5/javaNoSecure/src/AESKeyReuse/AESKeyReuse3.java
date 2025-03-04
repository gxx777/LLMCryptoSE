import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESKeyReuse3 {

    private static SecretKey secretKey;

    public static void main(String[] args) throws Exception {
        generateAESKey();

        String message1 = "Hello, Parties 1!";
        String message2 = "Hello, Parties 2!";
        String message3 = "Hello, Parties 3!";

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

    private static void generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        secretKey = keyGenerator.generateKey();
    }

    private static String encrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}