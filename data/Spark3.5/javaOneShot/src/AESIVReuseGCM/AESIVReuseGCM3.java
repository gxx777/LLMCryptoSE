import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM3 {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    public static void main(String[] args) throws Exception {
        // Generate random key and IV for each participant
        SecretKey key1 = generateKey();
        SecretKey key2 = generateKey();
        SecretKey key3 = generateKey();
        byte[] iv1 = generateIV();
        byte[] iv2 = generateIV();
        byte[] iv3 = generateIV();

        // Encrypt messages for each participant
        String message1 = "Hello, participant 1!";
        String message2 = "Hello, participant 2!";
        String message3 = "Hello, participant 3!";
        String encryptedMessage1 = encrypt(message1, key1, iv1);
        String encryptedMessage2 = encrypt(message2, key2, iv2);
        String encryptedMessage3 = encrypt(message3, key3, iv3);

        // Send encrypted messages to participants (simulated here)
        System.out.println("Encrypted message for participant 1: " + encryptedMessage1);
        System.out.println("Encrypted message for participant 2: " + encryptedMessage2);
        System.out.println("Encrypted message for participant 3: " + encryptedMessage3);

        // Decrypt messages from participants (simulated here)
        String decryptedMessage1 = decrypt(encryptedMessage1, key1, iv1);
        String decryptedMessage2 = decrypt(encryptedMessage2, key2, iv2);
        String decryptedMessage3 = decrypt(encryptedMessage3, key3, iv3);

        System.out.println("Decrypted message from participant 1: " + decryptedMessage1);
        System.out.println("Decrypted message from participant 2: " + decryptedMessage2);
        System.out.println("Decrypted message from participant 3: " + decryptedMessage3);
    }

    private static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    private static byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private static String encrypt(String plainText, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encryptedBytes.length);
        byteBuffer.put(iv);
        byteBuffer.put(encryptedBytes);
        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }

    private static String decrypt(String encryptedText, SecretKey key, byte[] iv) throws Exception {
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        ByteBuffer byteBuffer = ByteBuffer.wrap(decodedBytes);
        byte[] receivedIv = new byte[IV_LENGTH];
        byteBuffer.get(receivedIv);
        byte[] encryptedBytes = new byte[byteBuffer.remaining()];
        byteBuffer.get(encryptedBytes);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, receivedIv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        return new String(cipher.doFinal(encryptedBytes));
    }
}