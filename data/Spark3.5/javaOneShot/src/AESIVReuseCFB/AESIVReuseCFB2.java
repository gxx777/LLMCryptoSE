import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCFB2 {
    private static final String ALGORITHM = "AES/CFB/NoPadding";
    private static final int KEY_SIZE = 128;
    private static final int IV_SIZE = 16;

    public static void main(String[] args) throws Exception {
        String message1 = "Hello, Party 1!";
        String message2 = "Hello, Party 2!";
        String message3 = "Hello, Party 3!";

        // Generate a random key and IV for each party
        byte[] key1 = generateRandomBytes(KEY_SIZE / 8);
        byte[] iv1 = generateRandomBytes(IV_SIZE);
        byte[] key2 = generateRandomBytes(KEY_SIZE / 8);
        byte[] iv2 = generateRandomBytes(IV_SIZE);
        byte[] key3 = generateRandomBytes(KEY_SIZE / 8);
        byte[] iv3 = generateRandomBytes(IV_SIZE);

        // Encrypt messages for each party
        String encryptedMessage1 = encrypt(message1, key1, iv1);
        String encryptedMessage2 = encrypt(message2, key2, iv2);
        String encryptedMessage3 = encrypt(message3, key3, iv3);

        System.out.println("Encrypted message for Party 1: " + encryptedMessage1);
        System.out.println("Encrypted message for Party 2: " + encryptedMessage2);
        System.out.println("Encrypted message for Party 3: " + encryptedMessage3);
    }

    private static byte[] generateRandomBytes(int size) {
        byte[] bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private static String encrypt(String message, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}