import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCBC4 {

    private static final String key = "secretkey1234567";
    private static final String IV = "abcdefgh12345678";

    public static String encrypt(String message, String key, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedMessage, String key, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(original);
    }

    public static void main(String[] args) {
        String message1 = "Hello from Participant 1";
        String message2 = "Hello from Participant 2";
        String message3 = "Hello from Participant 3";

        try {
            // Participant 1 encrypts message for Participant 2
            String encryptedMessage1to2 = encrypt(message1, key, IV);

            // Participant 2 decrypts message from Participant 1
            String decryptedMessage1to2 = decrypt(encryptedMessage1to2, key, IV);
            System.out.println("Participant 2 received: " + decryptedMessage1to2);

            // Participant 2 encrypts message for Participant 3
            String encryptedMessage2to3 = encrypt(message2, key, IV);

            // Participant 3 decrypts message from Participant 2
            String decryptedMessage2to3 = decrypt(encryptedMessage2to3, key, IV);
            System.out.println("Participant 3 received: " + decryptedMessage2to3);

            // Participant 3 encrypts message for Participant 1
            String encryptedMessage3to1 = encrypt(message3, key, IV);

            // Participant 1 decrypts message from Participant 3
            String decryptedMessage3to1 = decrypt(encryptedMessage3to1, key, IV);
            System.out.println("Participant 1 received: " + decryptedMessage3to1);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}