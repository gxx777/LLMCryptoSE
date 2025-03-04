import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESIVReuseOFB1 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/OFB/PKCS5Padding";
    private static final int KEY_SIZE = 128;

    public static void main(String[] args) throws Exception {
        // Generate a secret key for AES encryption
        SecretKey secretKey = generateSecretKey();

        // Create an initialization vector (IV) for OFB mode
        byte[] iv = new byte[16];
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Encrypt and send messages to three different parties
        String message1 = "Hello, Party 1!";
        String message2 = "Hello, Party 2!";
        String message3 = "Hello, Party 3!";

        String encryptedMessage1 = encrypt(secretKey, ivParameterSpec, message1);
        String encryptedMessage2 = encrypt(secretKey, ivParameterSpec, message2);
        String encryptedMessage3 = encrypt(secretKey, ivParameterSpec, message3);

        System.out.println("Encrypted message for Party 1: " + encryptedMessage1);
        System.out.println("Encrypted message for Party 2: " + encryptedMessage2);
        System.out.println("Encrypted message for Party 3: " + encryptedMessage3);
    }

    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    private static String encrypt(SecretKey secretKey, IvParameterSpec ivParameterSpec, String message) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}