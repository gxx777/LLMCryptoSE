import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM4 {

    private static final String AES_MODE = "AES/GCM/NoPadding";
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 128;

    public static void main(String[] args) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_MODE);

        // Generate a random AES key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();

        // Generate a random IV
        byte[] iv = new byte[IV_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);

        // Encrypt and send message to participant 1
        String message1 = "Hello participant 1!";
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] encryptedMessage1 = cipher.doFinal(message1.getBytes());
        System.out.println("Encrypted message for participant 1: " + Base64.getEncoder().encodeToString(encryptedMessage1));

        // Encrypt and send message to participant 2
        String message2 = "Hello participant 2!";
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] encryptedMessage2 = cipher.doFinal(message2.getBytes());
        System.out.println("Encrypted message for participant 2: " + Base64.getEncoder().encodeToString(encryptedMessage2));

        // Encrypt and send message to participant 3
        String message3 = "Hello participant 3!";
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] encryptedMessage3 = cipher.doFinal(message3.getBytes());
        System.out.println("Encrypted message for participant 3: " + Base64.getEncoder().encodeToString(encryptedMessage3));
    }
}