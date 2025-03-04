import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCFB4 {

    private static final String ALGORITHM = "AES/CFB4/NoPadding";
    private static final int KEY_LENGTH = 128;
    private static final int IV_LENGTH = 16;

    public static void main(String[] args) throws Exception {
        String message1 = "Hello, Party1!";
        String message2 = "Hello, Party2!";
        String message3 = "Hello, Party3!";

        sendMessage(message1);
        sendMessage(message2);
        sendMessage(message3);
    }

    private static void sendMessage(String message) throws Exception {
        byte[] encryptedMessage = encrypt(message);
        System.out.println("Encrypted message: " + Base64.getEncoder().encodeToString(encryptedMessage));

        String decryptedMessage = decrypt(encryptedMessage);
        System.out.println("Decrypted message: " + decryptedMessage);
    }

    private static byte[] encrypt(String message) throws Exception {
        byte[] keyBytes = generateRandomKey();
        byte[] ivBytes = generateRandomIV();

        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        return cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
    }

    private static String decrypt(byte[] encryptedMessage) throws Exception {
        byte[] keyBytes = generateRandomKey();
        byte[] ivBytes = generateRandomIV();

        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        byte[] decryptedMessageBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedMessageBytes, StandardCharsets.UTF_8);
    }

    private static byte[] generateRandomKey() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] keyBytes = new byte[KEY_LENGTH / 8];
        secureRandom.nextBytes(keyBytes);
        return keyBytes;
    }

    private static byte[] generateRandomIV() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] ivBytes = new byte[IV_LENGTH / 8];
        secureRandom.nextBytes(ivBytes);
        return ivBytes;
    }
}