import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

public class AESIVReuseGCM4 {

    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    public static void main(String[] args) throws Exception {
        // Generate a random AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        // Generate a random IV
        byte[] iv1 = generateIV();
        byte[] iv2 = generateIV();
        byte[] iv3 = generateIV();

        // Encrypt and send message to participant 1
        String message1 = "Message for participant 1";
        byte[] encryptedMessage1 = encrypt(key, iv1, message1);
        System.out.println("Encrypted message 1: " + Base64.getEncoder().encodeToString(encryptedMessage1));

        // Encrypt and send message to participant 2
        String message2 = "Message for participant 2";
        byte[] encryptedMessage2 = encrypt(key, iv2, message2);
        System.out.println("Encrypted message 2: " + Base64.getEncoder().encodeToString(encryptedMessage2));

        // Encrypt and send message to participant 3
        String message3 = "Message for participant 3";
        byte[] encryptedMessage3 = encrypt(key, iv3, message3);
        System.out.println("Encrypted message 3: " + Base64.getEncoder().encodeToString(encryptedMessage3));
    }

    public static byte[] encrypt(SecretKey key, byte[] iv, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        AlgorithmParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] encrypted = cipher.doFinal(message.getBytes());
        return encrypted;
    }

    public static byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }
}