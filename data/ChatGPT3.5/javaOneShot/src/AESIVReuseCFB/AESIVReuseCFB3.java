import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCFB3 {

    private static final String AES_ALGORITHM = "AES";
    private static final String CIPHER_MODE = "AES/CFB/PKCS5Padding";

    private static final byte[] key = generateRandomKey();
    private static final byte[] ivSender1 = generateRandomIV();
    private static final byte[] ivSender2 = generateRandomIV();
    private static final byte[] ivSender3 = generateRandomIV();

    public static String encrypt(String message, byte[] iv, byte[] key) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_MODE);
            SecretKeySpec secretKey = new SecretKeySpec(key, AES_ALGORITHM);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            byte[] encrypted = cipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String encryptedMessage, byte[] iv, byte[] key) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_MODE);
            SecretKeySpec secretKey = new SecretKeySpec(key, AES_ALGORITHM);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            return new String(decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static byte[] generateRandomKey() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return key;
    }

    private static byte[] generateRandomIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static void main(String[] args) {
        String message = "Hello, World!";

        // Sender 1
        String encryptedMessage1 = encrypt(message, ivSender1, key);
        System.out.println("Encrypted Message from Sender 1: " + encryptedMessage1);

        String decryptedMessage1 = decrypt(encryptedMessage1, ivSender1, key);
        System.out.println("Decrypted Message for Sender 1: " + decryptedMessage1);

        // Sender 2
        String encryptedMessage2 = encrypt(message, ivSender2, key);
        System.out.println("Encrypted Message from Sender 2: " + encryptedMessage2);

        String decryptedMessage2 = decrypt(encryptedMessage2, ivSender2, key);
        System.out.println("Decrypted Message for Sender 2: " + decryptedMessage2);

        // Sender 3
        String encryptedMessage3 = encrypt(message, ivSender3, key);
        System.out.println("Encrypted Message from Sender 3: " + encryptedMessage3);

        String decryptedMessage3 = decrypt(encryptedMessage3, ivSender3, key);
        System.out.println("Decrypted Message for Sender 3: " + decryptedMessage3);
    }
}