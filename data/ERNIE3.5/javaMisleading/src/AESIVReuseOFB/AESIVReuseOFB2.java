import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseOFB2 {

    private static final String ALGORITHM = "AES/OFB/NoPadding";
    private static final byte[] KEY = "ThisIsASecretKey123456".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV = "ThisIsAnInitializationVector".getBytes(StandardCharsets.UTF_8);

    public static String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            String message1 = "Hello, Party A!";
            String message2 = "Hi, Party B!";
            String message3 = "Good day, Party C!";

            String encryptedMessage1 = encrypt(message1);
            String encryptedMessage2 = encrypt(message2);
            String encryptedMessage3 = encrypt(message3);

            System.out.println("Encrypted Message 1: " + encryptedMessage1);
            System.out.println("Encrypted Message 2: " + encryptedMessage2);
            System.out.println("Encrypted Message 3: " + encryptedMessage3);

            String decryptedMessage1 = decrypt(encryptedMessage1);
            String decryptedMessage2 = decrypt(encryptedMessage2);
            String decryptedMessage3 = decrypt(encryptedMessage3);

            System.out.println("Decrypted Message 1: " + decryptedMessage1);
            System.out.println("Decrypted Message 2: " + decryptedMessage2);
            System.out.println("Decrypted Message 3: " + decryptedMessage3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}