import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM1 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    public static void main(String[] args) throws Exception {
        // Generate a random key for each participant
        SecretKey key1 = generateKey();
        SecretKey key2 = generateKey();
        SecretKey key3 = generateKey();

        // Encrypt and send messages
        byte[] encryptedMessage1 = encrypt("Hello, participant 1!", key1);
        byte[] encryptedMessage2 = encrypt("Hello, participant 2!", key2);
        byte[] encryptedMessage3 = encrypt("Hello, participant 3!", key3);

        // Decrypt messages
        String decryptedMessage1 = decrypt(encryptedMessage1, key1);
        String decryptedMessage2 = decrypt(encryptedMessage2, key2);
        String decryptedMessage3 = decrypt(encryptedMessage3, key3);

        System.out.println("Decrypted message 1: " + decryptedMessage1);
        System.out.println("Decrypted message 2: " + decryptedMessage2);
        System.out.println("Decrypted message 3: " + decryptedMessage3);
    }

    private static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    private static byte[] encrypt(String plainText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        byte[] encryptedText = cipher.doFinal(plainText.getBytes());
        ByteBuffer byteBuffer = ByteBuffer.allocate(IV_LENGTH + encryptedText.length);
        byteBuffer.put(iv);
        byteBuffer.put(encryptedText);
        return byteBuffer.array();
    }

    private static String decrypt(byte[] encryptedMessage, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedMessage);
        byte[] iv = new byte[IV_LENGTH];
        byteBuffer.get(iv);
        byte[] encryptedText = new byte[byteBuffer.remaining()];
        byteBuffer.get(encryptedText);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        byte[] decryptedText = cipher.doFinal(encryptedText);
        return new String(decryptedText);
    }
}