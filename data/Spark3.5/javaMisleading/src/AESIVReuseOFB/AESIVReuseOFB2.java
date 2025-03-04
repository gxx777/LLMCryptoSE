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
    private static final int IV_SIZE = 16;

    public static void main(String[] args) throws Exception {
        // Generate a random secret key
        SecretKey secretKey = generateSecretKey();

        // Generate a random initial vector (IV)
        byte[] iv = generateRandomIV();

        // Create the Cipher instances for each participant
        Cipher cipher1 = createCipher(secretKey, iv);
        Cipher cipher2 = createCipher(secretKey, iv);
        Cipher cipher3 = createCipher(secretKey, iv);

        // Encrypt and decrypt messages for each participant
        String message1 = "Hello, participant 1!";
        String message2 = "Hello, participant 2!";
        String message3 = "Hello, participant 3!";

        String encryptedMessage1 = encrypt(cipher1, message1);
        String encryptedMessage2 = encrypt(cipher2, message2);
        String encryptedMessage3 = encrypt(cipher3, message3);

        System.out.println("Encrypted messages:");
        System.out.println("Participant 1: " + encryptedMessage1);
        System.out.println("Participant 2: " + encryptedMessage2);
        System.out.println("Participant 3: " + encryptedMessage3);

        String decryptedMessage1 = decrypt(cipher1, encryptedMessage1);
        String decryptedMessage2 = decrypt(cipher2, encryptedMessage2);
        String decryptedMessage3 = decrypt(cipher3, encryptedMessage3);

        System.out.println("Decrypted messages:");
        System.out.println("Participant 1: " + decryptedMessage1);
        System.out.println("Participant 2: " + decryptedMessage2);
        System.out.println("Participant 3: " + decryptedMessage3);
    }

    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    private static byte[] generateRandomIV() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private static Cipher createCipher(SecretKey secretKey, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return cipher;
    }

    private static String encrypt(Cipher cipher, String message) throws Exception {
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(Cipher cipher, String encryptedMessage) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }
}