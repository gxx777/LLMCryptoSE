import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESKeyReuse2 {
    private static final String ALGORITHM = "AES";
    private static final int KEY_SIZE = 128;

    public static void main(String[] args) throws Exception {
        String message1 = "Message from party 1";
        String message2 = "Message from party 2";
        String message3 = "Message from party 3";

        SecretKey secretKey = generateSecretKey();

        String encryptedMessage1 = encrypt(message1, secretKey);
        String encryptedMessage2 = encrypt(message2, secretKey);
        String encryptedMessage3 = encrypt(message3, secretKey);

        System.out.println("Encrypted messages:");
        System.out.println(encryptedMessage1);
        System.out.println(encryptedMessage2);
        System.out.println(encryptedMessage3);

        System.out.println("Decrypted messages:");
        System.out.println(decrypt(encryptedMessage1, secretKey));
        System.out.println(decrypt(encryptedMessage2, secretKey));
        System.out.println(decrypt(encryptedMessage3, secretKey));
    }

    private static SecretKey generateSecretKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    private static String encrypt(String message, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String encryptedMessage, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}