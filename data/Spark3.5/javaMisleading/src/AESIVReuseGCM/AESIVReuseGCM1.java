import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM1 {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    public static void main(String[] args) throws Exception {
        // Generate a random secret key
        SecureRandom secureRandom = new SecureRandom();
        byte[] keyBytes = new byte[16];
        secureRandom.nextBytes(keyBytes);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        // Generate a random initial vector (IV)
        byte[] ivBytes = new byte[IV_LENGTH];
        secureRandom.nextBytes(ivBytes);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, ivBytes);

        // Encrypt and decrypt messages for three different parties
        String message1 = "Hello, Party 1!";
        String message2 = "Hello, Party 2!";
        String message3 = "Hello, Party 3!";

        String encryptedMessage1 = encrypt(secretKey, gcmParameterSpec, message1);
        String encryptedMessage2 = encrypt(secretKey, gcmParameterSpec, message2);
        String encryptedMessage3 = encrypt(secretKey, gcmParameterSpec, message3);

        System.out.println("Encrypted Message 1: " + encryptedMessage1);
        System.out.println("Encrypted Message 2: " + encryptedMessage2);
        System.out.println("Encrypted Message 3: " + encryptedMessage3);

        String decryptedMessage1 = decrypt(secretKey, gcmParameterSpec, encryptedMessage1);
        String decryptedMessage2 = decrypt(secretKey, gcmParameterSpec, encryptedMessage2);
        String decryptedMessage3 = decrypt(secretKey, gcmParameterSpec, encryptedMessage3);

        System.out.println("Decrypted Message 1: " + decryptedMessage1);
        System.out.println("Decrypted Message 2: " + decryptedMessage2);
        System.out.println("Decrypted Message 3: " + decryptedMessage3);
    }

    private static String encrypt(SecretKey secretKey, GCMParameterSpec gcmParameterSpec, String message) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(SecretKey secretKey, GCMParameterSpec gcmParameterSpec, String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }
}