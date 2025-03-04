import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCFB1 {

    public static void main(String[] args) throws Exception {
        String message1 = "Hello, Parties 1!";
        String message2 = "Hello, Parties 2!";
        String message3 = "Hello, Parties 3!";

        // Generate random keys and IVs for each party
        byte[] key1 = generateRandomBytes(16);
        byte[] key2 = generateRandomBytes(16);
        byte[] key3 = generateRandomBytes(16);

        byte[] iv1 = generateRandomBytes(16);
        byte[] iv2 = generateRandomBytes(16);
        byte[] iv3 = generateRandomBytes(16);

        // Encrypt messages for each party
        String encryptedMessage1 = encrypt(message1, key1, iv1);
        String encryptedMessage2 = encrypt(message2, key2, iv2);
        String encryptedMessage3 = encrypt(message3, key3, iv3);

        System.out.println("Encrypted Message 1: " + encryptedMessage1);
        System.out.println("Encrypted Message 2: " + encryptedMessage2);
        System.out.println("Encrypted Message 3: " + encryptedMessage3);
    }

    private static byte[] generateRandomBytes(int length) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    private static String encrypt(String message, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}