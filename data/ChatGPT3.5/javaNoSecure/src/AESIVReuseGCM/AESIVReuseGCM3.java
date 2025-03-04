import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class AESIVReuseGCM3 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;

    public static void main(String[] args) {
        try {
            // Generate a random AES key
            SecretKey secretKey = generateSecretKey();

            // Generate random IV for each participant
            byte[] ivParticipant1 = generateIV();
            byte[] ivParticipant2 = generateIV();
            byte[] ivParticipant3 = generateIV();

            // Create GCMParameterSpec using the IV and TAG length
            GCMParameterSpec gcmParameterSpec1 = new GCMParameterSpec(TAG_LENGTH_BIT, ivParticipant1);
            GCMParameterSpec gcmParameterSpec2 = new GCMParameterSpec(TAG_LENGTH_BIT, ivParticipant2);
            GCMParameterSpec gcmParameterSpec3 = new GCMParameterSpec(TAG_LENGTH_BIT, ivParticipant3);

            // Initialize the cipher with AES key and GCM parameters
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);

            // Participant 1 sends message to Participant 2
            String message1to2 = "Hello Participant 2!";
            byte[] encryptedMessage1to2 = encrypt(message1to2, secretKey, gcmParameterSpec1);
            String decryptedMessage1to2 = decrypt(encryptedMessage1to2, secretKey, gcmParameterSpec2);
            System.out.println("Participant 1 sent to Participant 2: " + decryptedMessage1to2);

            // Participant 2 sends message to Participant 3
            String message2to3 = "Hello Participant 3!";
            byte[] encryptedMessage2to3 = encrypt(message2to3, secretKey, gcmParameterSpec2);
            String decryptedMessage2to3 = decrypt(encryptedMessage2to3, secretKey, gcmParameterSpec3);
            System.out.println("Participant 2 sent to Participant 3: " + decryptedMessage2to3);

            // Participant 3 sends message to Participant 1
            String message3to1 = "Hello Participant 1!";
            byte[] encryptedMessage3to1 = encrypt(message3to1, secretKey, gcmParameterSpec3);
            String decryptedMessage3to1 = decrypt(encryptedMessage3to1, secretKey, gcmParameterSpec1);
            System.out.println("Participant 3 sent to Participant 1: " + decryptedMessage3to1);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[16];
        secureRandom.nextBytes(key);
        return new SecretKeySpec(key, ALGORITHM);
    }

    private static byte[] generateIV() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        return iv;
    }

    private static byte[] encrypt(String message, SecretKey secretKey, GCMParameterSpec gcmParameterSpec) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] cipherText = cipher.doFinal(message.getBytes());
        return cipherText;
    }

    private static String decrypt(byte[] cipherText, SecretKey secretKey, GCMParameterSpec gcmParameterSpec) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] decryptedText = cipher.doFinal(cipherText);
        return new String(decryptedText);
    }
}