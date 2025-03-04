import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseOFB3 {
    private static final String ALGORITHM = "AES/OFB/PKCS5Padding";
    private static final int KEY_SIZE = 128;
    private static final int IV_SIZE = 16;

    public static void main(String[] args) throws Exception {
        String message = "Hello, this is a secret message!";
        SecretKey secretKey = generateSecretKey();
        IvParameterSpec iv = generateIV();

        String encryptedMessage1 = encrypt(message, secretKey, iv);
        String encryptedMessage2 = encrypt(message, secretKey, iv);
        String encryptedMessage3 = encrypt(message, secretKey, iv);

        System.out.println("Encrypted message 1: " + encryptedMessage1);
        System.out.println("Encrypted message 2: " + encryptedMessage2);
        System.out.println("Encrypted message 3: " + encryptedMessage3);
    }

    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    private static IvParameterSpec generateIV() {
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