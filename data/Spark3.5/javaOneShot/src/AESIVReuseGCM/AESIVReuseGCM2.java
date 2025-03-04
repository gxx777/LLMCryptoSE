import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM2 {
    private static final int GCM_TAG_LENGTH = 16;
    private static final int IV_LENGTH = 12;

    public static void main(String[] args) throws Exception {
        // Generate a random AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();

        // Generate random IVs for each participant
        byte[] iv1 = generateRandomIV();
        byte[] iv2 = generateRandomIV();
        byte[] iv3 = generateRandomIV();

        // Encrypt messages for each participant
        String message1 = "Hello, participant 1!";
        String message2 = "Hello, participant 2!";
        String message3 = "Hello, participant 3!";

        String encryptedMessage1 = encrypt(message1, secretKey, iv1);
        String encryptedMessage2 = encrypt(message2, secretKey, iv2);
        String encryptedMessage3 = encrypt(message3, secretKey, iv3);

        System.out.println("Encrypted message for participant 1: " + encryptedMessage1);
        System.out.println("Encrypted message for participant 2: " + encryptedMessage2);
        System.out.println("Encrypted message for participant 3: " + encryptedMessage3);
    }

    private static byte[] generateRandomIV() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private static String encrypt(String plaintext, SecretKey secretKey, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + ciphertext.length);
        byteBuffer.put(iv);
        byteBuffer.put(ciphertext);

        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }
}