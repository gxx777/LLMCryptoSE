import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCTR1 {

    private static final String AES_KEY = "0123456789abcdef";
    private static final String AES_IV = "1234567890abcdef";

    public static void main(String[] args) {
        String message1 = "Message from participant 1";
        String message2 = "Message from participant 2";
        String message3 = "Message from participant 3";

        String encryptedMessage1 = encrypt(message1, AES_KEY, AES_IV);
        String encryptedMessage2 = encrypt(message2, AES_KEY, AES_IV);
        String encryptedMessage3 = encrypt(message3, AES_KEY, AES_IV);

        System.out.println("Participant 1 message: " + decrypt(encryptedMessage1, AES_KEY, AES_IV));
        System.out.println("Participant 2 message: " + decrypt(encryptedMessage2, AES_KEY, AES_IV));
        System.out.println("Participant 3 message: " + decrypt(encryptedMessage3, AES_KEY, AES_IV));
    }

    public static String encrypt(String message, String key, String iv) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] encryptedBytes = cipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String encryptedMessage, String key, String iv) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}