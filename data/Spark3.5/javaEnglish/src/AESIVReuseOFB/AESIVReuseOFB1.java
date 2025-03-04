import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseOFB1 {
    private static final String ALGORITHM = "AES/OFB/PKCS5Padding";
    private static final int KEY_SIZE = 128;
    private static final int IV_SIZE = 16;

    public static void main(String[] args) throws Exception {
        // Generate a random secret key
        SecretKey secretKey = generateSecretKey();

        // Generate random initialization vectors for each participant
        IvParameterSpec iv1 = generateRandomIV();
        IvParameterSpec iv2 = generateRandomIV();
        IvParameterSpec iv3 = generateRandomIV();

        // Encrypt messages for three different participants separately using AES in OFB mode
        String message1 = "Hello, participant 1!";
        String message2 = "Hello, participant 2!";
        String message3 = "Hello, participant 3!";

        String encryptedMessage1 = encrypt(message1, secretKey, iv1);
        String encryptedMessage2 = encrypt(message2, secretKey, iv2);
        String encryptedMessage3 = encrypt(message3, secretKey, iv3);

        System.out.println("Encrypted message for participant 1: " + encryptedMessage1);
        System.out.println("Encrypted message for participant 2: " + encryptedMessage2);
        System.out.println("Encrypted message for participant 3: " + encryptedMessage3);
    }

    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    private static IvParameterSpec generateRandomIV() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private static String encrypt(String message, SecretKey secretKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}