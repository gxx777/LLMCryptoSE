import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR3 {
    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final int KEY_SIZE = 128;
    private static final int IV_SIZE = 16;

    public static void main(String[] args) throws Exception {
        // 生成密钥
        SecretKey secretKey = generateKey();

        // 发送方1
        byte[] iv1 = generateIV();
        String message1 = "Hello, Sender 1!";
        String encryptedMessage1 = encrypt(secretKey, iv1, message1);
        System.out.println("Encrypted message from Sender 1: " + encryptedMessage1);

        // 发送方2
        byte[] iv2 = generateIV();
        String message2 = "Hello, Sender 2!";
        String encryptedMessage2 = encrypt(secretKey, iv2, message2);
        System.out.println("Encrypted message from Sender 2: " + encryptedMessage2);

        // 发送方3
        byte[] iv3 = generateIV();
        String message3 = "Hello, Sender 3!";
        String encryptedMessage3 = encrypt(secretKey, iv3, message3);
        System.out.println("Encrypted message from Sender 3: " + encryptedMessage3);
    }

    private static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    private static byte[] generateIV() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private static String encrypt(SecretKey secretKey, byte[] iv, String message) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}