import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class AESIVReuseCFB3 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CFB/NoPadding";
    private static final int KEY_SIZE = 16;
    private static final int IV_SIZE = 16;

    private static byte[] generateKey() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[KEY_SIZE];
        secureRandom.nextBytes(key);
        return key;
    }

    private static byte[] generateIV() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[IV_SIZE];
        secureRandom.nextBytes(iv);
        return iv;
    }

    public static byte[] encrypt(String message, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
    }

    public static String decrypt(byte[] cipherText, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(cipherText);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            byte[] key1 = generateKey();
            byte[] iv1 = generateIV();
            byte[] key2 = generateKey();
            byte[] iv2 = generateIV();
            byte[] key3 = generateKey();
            byte[] iv3 = generateIV();

            String message1 = "Hello, participant 1!";
            String message2 = "Hello, participant 2!";
            String message3 = "Hello, participant 3!";

            byte[] encryptedMessage1 = encrypt(message1, key1, iv1);
            byte[] encryptedMessage2 = encrypt(message2, key2, iv2);
            byte[] encryptedMessage3 = encrypt(message3, key3, iv3);

            String decryptedMessage1 = decrypt(encryptedMessage1, key1, iv1);
            String decryptedMessage2 = decrypt(encryptedMessage2, key2, iv2);
            String decryptedMessage3 = decrypt(encryptedMessage3, key3, iv3);

            System.out.println("Decrypted message for participant 1: " + decryptedMessage1);
            System.out.println("Decrypted message for participant 2: " + decryptedMessage2);
            System.out.println("Decrypted message for participant 3: " + decryptedMessage3);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}