import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCTR4 {

    private static final String AES_KEY = "0123456789abcdef";
    private static final String AES_IV = "fedcba9876543210";

    public static String encryptMessage(String message, String key) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

        IvParameterSpec iv = new IvParameterSpec(AES_IV.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);

        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decryptMessage(String encryptedMessage, String key) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

        IvParameterSpec iv = new IvParameterSpec(AES_IV.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);

        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            String message = "Hello, world!";
            String key1 = "0123456789abcdef";
            String key2 = "abcdef0123456789";
            String key3 = "fedcba9876543210";

            String encryptedMessage1 = encryptMessage(message, key1);
            String encryptedMessage2 = encryptMessage(message, key2);
            String encryptedMessage3 = encryptMessage(message, key3);

            System.out.println("Encrypted Message 1: " + encryptedMessage1);
            System.out.println("Encrypted Message 2: " + encryptedMessage2);
            System.out.println("Encrypted Message 3: " + encryptedMessage3);

            String decryptedMessage1 = decryptMessage(encryptedMessage1, key1);
            String decryptedMessage2 = decryptMessage(encryptedMessage2, key2);
            String decryptedMessage3 = decryptMessage(encryptedMessage3, key3);

            System.out.println("Decrypted Message 1: " + decryptedMessage1);
            System.out.println("Decrypted Message 2: " + decryptedMessage2);
            System.out.println("Decrypted Message 3: " + decryptedMessage3);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}