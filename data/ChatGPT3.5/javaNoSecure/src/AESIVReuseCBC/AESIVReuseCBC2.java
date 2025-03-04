import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESIVReuseCBC2 {

    private static final String key = "0123456789abcdef"; // 16字节的AES密钥
    private static final String IV = "1234567890abcdef"; // 16字节的初始向量

    public static void main(String[] args) {
        String message1 = "Hello, participant 1!";
        String message2 = "Hello, participant 2!";
        String message3 = "Hello, participant 3!";

        String encryptedMessage1 = encrypt(message1, key, IV);
        String encryptedMessage2 = encrypt(message2, key, IV);
        String encryptedMessage3 = encrypt(message3, key, IV);

        System.out.println("Encrypted message 1: " + encryptedMessage1);
        System.out.println("Encrypted message 2: " + encryptedMessage2);
        System.out.println("Encrypted message 3: " + encryptedMessage3);
    }

    public static String encrypt(String plaintext, String key, String IV) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes());

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());

            return new String(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}