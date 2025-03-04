import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR2 {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CTR/PKCS5Padding";

    public static void main(String[] args) throws Exception {
        // Generate a random secret key for each participant
        SecretKey secretKey1 = generateSecretKey();
        SecretKey secretKey2 = generateSecretKey();
        SecretKey secretKey3 = generateSecretKey();

        // Generate a random initialization vector (IV) for each participant
        IvParameterSpec iv1 = generateIV();
        IvParameterSpec iv2 = generateIV();
        IvParameterSpec iv3 = generateIV();

        // Encrypt and decrypt messages for each participant
        String message1 = "Hello, participant 1!";
        String message2 = "Hello, participant 2!";
        String message3 = "Hello, participant 3!";

        String encryptedMessage1 = encrypt(message1, secretKey1, iv1);
        String encryptedMessage2 = encrypt(message2, secretKey2, iv2);
        String encryptedMessage3 = encrypt(message3, secretKey3, iv3);

        System.out.println("Encrypted messages:");
        System.out.println("Participant 1: " + encryptedMessage1);
        System.out.println("Participant 2: " + encryptedMessage2);
        System.out.println("Participant 3: " + encryptedMessage3);

        String decryptedMessage1 = decrypt(encryptedMessage1, secretKey1, iv1);
        String decryptedMessage2 = decrypt(encryptedMessage2, secretKey2, iv2);
        String decryptedMessage3 = decrypt(encryptedMessage3, secretKey3, iv3);

        System.out.println("Decrypted messages:");
        System.out.println("Participant 1: " + decryptedMessage1);
        System.out.println("Participant 2: " + decryptedMessage2);
        System.out.println("Participant 3: " + decryptedMessage3);
    }

    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(256);
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

    private static String decrypt(String encryptedMessage, SecretKey secretKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes);
    }
}