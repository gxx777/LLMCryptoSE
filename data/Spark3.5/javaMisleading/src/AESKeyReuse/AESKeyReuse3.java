import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESKeyReuse3 {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    public static void main(String[] args) throws Exception {
        String message1 = "Message from party 1";
        String message2 = "Message from party 2";
        String message3 = "Message from party 3";

        SecretKey secretKey = generateSecretKey();
        byte[] iv = generateInitializationVector();

        String encryptedMessage1 = encrypt(message1, secretKey, iv);
        String encryptedMessage2 = encrypt(message2, secretKey, iv);
        String encryptedMessage3 = encrypt(message3, secretKey, iv);

        System.out.println("Encrypted message 1: " + encryptedMessage1);
        System.out.println("Encrypted message 2: " + encryptedMessage2);
        System.out.println("Encrypted message 3: " + encryptedMessage3);
    }

    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private static byte[] generateInitializationVector() {
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }

    private static String encrypt(String message, SecretKey secretKey, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}