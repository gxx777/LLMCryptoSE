import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCFB3 {
    private static final String KEY = "0123456789abcdef"; // 16-byte key for AES
    private static final String IV = "fedcba9876543210"; // 8-byte IV for CFB mode

    public static void main(String[] args) throws Exception {
        String message1 = "Message for Participant 1";
        String message2 = "Message for Participant 2";
        String message3 = "Message for Participant 3";

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
    }

    public static String encrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV.getBytes(StandardCharsets.UTF_8));

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV.getBytes(StandardCharsets.UTF_8));

        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}