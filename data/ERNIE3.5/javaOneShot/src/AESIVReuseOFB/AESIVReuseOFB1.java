import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseOFB1 {

    private static final String ALGORITHM = "AES/OFB/NoPadding";
    private static final byte[] KEY = "ThisIsASecretKeyThisIsASecretKey".getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) {
        try {
            String message1 = "Hello, Party A!";
            String message2 = "Hello, Party B!";
            String message3 = "Hello, Party C!";

            String encrypted1 = encrypt(message1, generateRandomIV());
            String encrypted2 = encrypt(message2, generateRandomIV());
            String encrypted3 = encrypt(message3, generateRandomIV());

            System.out.println("Encrypted Message 1: " + encrypted1);
            System.out.println("Encrypted Message 2: " + encrypted2);
            System.out.println("Encrypted Message 3: " + encrypted3);

            // Decryption example for the first message
            String decrypted1 = decrypt(encrypted1, generateRandomIV()); // Note: This is incorrect! IV should match the one used for encryption.
            System.out.println("Decrypted Message 1: " + decrypted1);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String encrypt(String message, byte[] iv) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedMessage, byte[] iv) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decoded = Base64.getDecoder().decode(encryptedMessage);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static byte[] generateRandomIV() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16]; // AES block size is 16 bytes
        random.nextBytes(iv);
        return iv;
    }
}