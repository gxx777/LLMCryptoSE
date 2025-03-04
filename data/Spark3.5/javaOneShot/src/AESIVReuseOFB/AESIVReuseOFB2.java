import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseOFB2 {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/OFB/PKCS5Padding";
    private static final int KEY_SIZE = 128;

    public static void main(String[] args) throws Exception {
        // Generate a random secret key for each participant
        SecretKey secretKey1 = generateSecretKey();
        SecretKey secretKey2 = generateSecretKey();
        SecretKey secretKey3 = generateSecretKey();

        // Generate a random initialization vector (IV) for each participant
        IvParameterSpec iv1 = generateIV();
        IvParameterSpec iv2 = generateIV();
        IvParameterSpec iv3 = generateIV();

        // Encrypt and send messages
        String message1 = "Hello, participant 1!";
        String message2 = "Hello, participant 2!";
        String message3 = "Hello, participant 3!";

        String encryptedMessage1 = encrypt(message1, secretKey1, iv1);
        String encryptedMessage2 = encrypt(message2, secretKey2, iv2);
        String encryptedMessage3 = encrypt(message3, secretKey3, iv3);

        System.out.println("Encrypted message for participant 1: " + encryptedMessage1);
        System.out.println("Encrypted message for participant 2: " + encryptedMessage2);
        System.out.println("Encrypted message for participant 3: " + encryptedMessage3);
    }

    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    private static IvParameterSpec generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private static String encrypt(String message, SecretKey secretKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}