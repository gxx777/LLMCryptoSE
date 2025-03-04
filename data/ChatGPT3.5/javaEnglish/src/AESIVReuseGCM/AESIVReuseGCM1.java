import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM1 {

    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;

    public static void main(String[] args) throws Exception {
        // Generate a random AES key
        byte[] aesKey = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(aesKey);
        SecretKey secretKey = new SecretKeySpec(aesKey, "AES");

        // Generate IV (nonce) for GCM
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);

        // Message to be encrypted and sent
        String message = "Hello, Participant 1!";
        byte[] encryptedMessage1 = encrypt(message, secretKey, gcmParameterSpec);
        System.out.println("Encrypted Message 1: " + Base64.getEncoder().encodeToString(encryptedMessage1));

        // New IV (nonce) for GCM
        secureRandom.nextBytes(iv);
        gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        
        // Message to be sent to second participant
        String message2 = "Hi, Participant 2!";
        byte[] encryptedMessage2 = encrypt(message2, secretKey, gcmParameterSpec);
        System.out.println("Encrypted Message 2: " + Base64.getEncoder().encodeToString(encryptedMessage2));

        // New IV (nonce) for GCM
        secureRandom.nextBytes(iv);
        gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);

        // Message to be sent to third participant
        String message3 = "Hey, Participant 3!";
        byte[] encryptedMessage3 = encrypt(message3, secretKey, gcmParameterSpec);
        System.out.println("Encrypted Message 3: " + Base64.getEncoder().encodeToString(encryptedMessage3));
    }

    private static byte[] encrypt(String plaintext, SecretKey secretKey, GCMParameterSpec gcmParameterSpec) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] cipherText = cipher.doFinal(plaintext.getBytes());
        return cipherText;
    }
}