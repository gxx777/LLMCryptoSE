import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR3 {

    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final int KEY_SIZE = 128; // AES key size in bits
    private static final byte[] KEY = generateRandomKey(KEY_SIZE);

    public static void main(String[] args) throws Exception {
        String[] recipients = {"Alice", "Bob", "Charlie"};
        String[] messages = {"Hello Alice", "Hello Bob", "Hello Charlie"};

        for (int i = 0; i < recipients.length; i++) {
            String message = messages[i];
            String encryptedMessage = encrypt(message, generateRandomIV(AESIVReuseCTR3.KEY_SIZE / 8));
            System.out.println("Sending encrypted message to " + recipients[i] + ": " + encryptedMessage);

            // For demonstration purposes, we'll assume the recipient receives the encrypted message and IV
            // They can then decrypt it using the same key and the provided IV
            String decryptedMessage = decrypt(encryptedMessage, AESIVReuseCTR3.KEY, generateRandomIV(AESIVReuseCTR3.KEY_SIZE / 8));
            System.out.println("Received decrypted message from " + recipients[i] + ": " + decryptedMessage);
        }
    }

    private static String encrypt(String message, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String encryptedMessage, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private static byte[] generateRandomKey(int keySize) {
        byte[] key = new byte[keySize / 8];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(key);
        return key;
    }

    private static byte[] generateRandomIV(int ivSize) {
        byte[] iv = new byte[ivSize];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        return iv;
    }
}