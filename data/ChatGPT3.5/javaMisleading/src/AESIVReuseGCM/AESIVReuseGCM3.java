import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM3 {

    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    public static void main(String[] args) throws Exception {
        // Generate AES secret key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();

        // Generate random IV
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);

        // Encrypt and send message to participant 1
        String message1 = "Message to Participant 1";
        byte[] encryptedMessage1 = encrypt(message1, secretKey, iv);
        System.out.println("Encrypted message to Participant 1: " + Base64.getEncoder().encodeToString(encryptedMessage1));

        // Encrypt and send message to participant 2
        String message2 = "Message to Participant 2";
        byte[] encryptedMessage2 = encrypt(message2, secretKey, iv);
        System.out.println("Encrypted message to Participant 2: " + Base64.getEncoder().encodeToString(encryptedMessage2));

        // Encrypt and send message to participant 3
        String message3 = "Message to Participant 3";
        byte[] encryptedMessage3 = encrypt(message3, secretKey, iv);
        System.out.println("Encrypted message to Participant 3: " + Base64.getEncoder().encodeToString(encryptedMessage3));
    }

    private static byte[] encrypt(String message, SecretKey secretKey, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        byte[] cipherText = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        return cipherText;
    }
}