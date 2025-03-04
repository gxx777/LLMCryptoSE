import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCBC1 {

    public static void main(String[] args) {
        try {
            // Generate AES key and IV
            String key = "0123456789abcdef";
            String iv = "abcdef9876543210";
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());

            // Message for participant 1
            String message1 = "This is a message for participant 1";
            String encryptedMessage1 = encrypt(message1, secretKey, ivParameterSpec);
            System.out.println("Encrypted message for participant 1: " + encryptedMessage1);

            // Message for participant 2
            String message2 = "This is a message for participant 2";
            String encryptedMessage2 = encrypt(message2, secretKey, ivParameterSpec);
            System.out.println("Encrypted message for participant 2: " + encryptedMessage2);

            // Message for participant 3
            String message3 = "This is a message for participant 3";
            String encryptedMessage3 = encrypt(message3, secretKey, ivParameterSpec);
            System.out.println("Encrypted message for participant 3: " + encryptedMessage3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String encrypt(String plaintext, SecretKeySpec secretKey, IvParameterSpec ivParameterSpec) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

}