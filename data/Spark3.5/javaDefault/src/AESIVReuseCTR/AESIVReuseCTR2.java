import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR2 {
    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final int IV_SIZE = 16;

    public static void main(String[] args) throws Exception {
        String message1 = "Hello, Party 1!";
        String message2 = "Hello, Party 2!";
        String message3 = "Hello, Party 3!";

        String key = generateRandomKey();
        byte[] iv = generateRandomIV();

        String encryptedMessage1 = encrypt(message1, key, iv);
        String encryptedMessage2 = encrypt(message2, key, iv);
        String encryptedMessage3 = encrypt(message3, key, iv);

        System.out.println("Encrypted Message 1: " + encryptedMessage1);
        System.out.println("Encrypted Message 2: " + encryptedMessage2);
        System.out.println("Encrypted Message 3: " + encryptedMessage3);
    }

    private static String generateRandomKey() {
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[32];
        random.nextBytes(keyBytes);
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    private static byte[] generateRandomIV() {
        SecureRandom random = new SecureRandom();
        byte[] ivBytes = new byte[IV_SIZE];
        random.nextBytes(ivBytes);
        return ivBytes;
    }

    private static String encrypt(String message, String key, byte[] iv) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.getDecoder().decode(key), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}