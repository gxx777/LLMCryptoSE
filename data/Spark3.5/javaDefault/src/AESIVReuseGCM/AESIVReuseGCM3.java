import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM3 {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    public static void main(String[] args) throws Exception {
        // Generate a random secret key
        SecretKey secretKey = generateSecretKey();

        // Encrypt and send messages for three different parties
        String message1 = "Hello, Party 1!";
        String message2 = "Hello, Party 2!";
        String message3 = "Hello, Party 3!";

        byte[] iv = generateIV();
        byte[] encryptedMessage1 = encrypt(secretKey, iv, message1.getBytes());
        byte[] encryptedMessage2 = encrypt(secretKey, iv, message2.getBytes());
        byte[] encryptedMessage3 = encrypt(secretKey, iv, message3.getBytes());

        System.out.println("Encrypted Message 1: " + Base64.getEncoder().encodeToString(encryptedMessage1));
        System.out.println("Encrypted Message 2: " + Base64.getEncoder().encodeToString(encryptedMessage2));
        System.out.println("Encrypted Message 3: " + Base64.getEncoder().encodeToString(encryptedMessage3));
    }

    private static SecretKey generateSecretKey() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return new SecretKeySpec(key, "AES");
    }

    private static byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private static byte[] encrypt(SecretKey secretKey, byte[] iv, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        return cipher.doFinal(plaintext);
    }
}