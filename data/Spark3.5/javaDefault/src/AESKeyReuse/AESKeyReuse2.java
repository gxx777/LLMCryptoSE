import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESKeyReuse2 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 128;
    private static final int IV_SIZE = 16;

    public static void main(String[] args) throws Exception {
        // Generate a random secret key
        SecretKey secretKey = generateSecretKey();

        // Generate random initialization vectors for each participant
        IvParameterSpec participant1IV = generateRandomIV();
        IvParameterSpec participant2IV = generateRandomIV();
        IvParameterSpec participant3IV = generateRandomIV();

        // Encrypt messages for each participant
        String participant1Message = "Hello, participant 1!";
        String participant2Message = "Hello, participant 2!";
        String participant3Message = "Hello, participant 3!";

        String encryptedParticipant1Message = encrypt(participant1Message, secretKey, participant1IV);
        String encryptedParticipant2Message = encrypt(participant2Message, secretKey, participant2IV);
        String encryptedParticipant3Message = encrypt(participant3Message, secretKey, participant3IV);

        System.out.println("Encrypted messages:");
        System.out.println("Participant 1: " + encryptedParticipant1Message);
        System.out.println("Participant 2: " + encryptedParticipant2Message);
        System.out.println("Participant 3: " + encryptedParticipant3Message);
    }

    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    private static IvParameterSpec generateRandomIV() {
        byte[] iv = new byte[IV_SIZE];
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