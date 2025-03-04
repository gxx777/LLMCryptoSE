import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESKeyReuse2 {

    private static final String ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 128;
    private static final int IV_SIZE = 16;

    public static void main(String[] args) throws Exception {
        // Generate a random secret key for each participant
        SecretKey participant1Key = generateSecretKey();
        SecretKey participant2Key = generateSecretKey();
        SecretKey participant3Key = generateSecretKey();

        // Encrypt and send messages
        String message1 = "Hello, participant 1!";
        String message2 = "Hello, participant 2!";
        String message3 = "Hello, participant 3!";

        String encryptedMessage1 = encrypt(message1, participant1Key);
        String encryptedMessage2 = encrypt(message2, participant2Key);
        String encryptedMessage3 = encrypt(message3, participant3Key);

        System.out.println("Encrypted messages:");
        System.out.println("Participant 1: " + encryptedMessage1);
        System.out.println("Participant 2: " + encryptedMessage2);
        System.out.println("Participant 3: " + encryptedMessage3);
    }

    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    private static String encrypt(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        byte[] encryptedMessageWithIv = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, encryptedMessageWithIv, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, encryptedMessageWithIv, iv.length, encryptedBytes.length);
        return Base64.getEncoder().encodeToString(encryptedMessageWithIv);
    }
}