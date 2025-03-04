import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESKeyReuse4 {
    private static SecretKey secretKey;

    static {
        try {
            // 生成一个AES密钥
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            secretKey = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static String encrypt(String plainText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        String message1 = "Hello from party 1";
        String message2 = "Hello from party 2";
        String message3 = "Hello from party 3";

        String encryptedMessage1 = encrypt(message1, secretKey);
        String encryptedMessage2 = encrypt(message2, secretKey);
        String encryptedMessage3 = encrypt(message3, secretKey);

        System.out.println("Encrypted messages:");
        System.out.println(encryptedMessage1);
        System.out.println(encryptedMessage2);
        System.out.println(encryptedMessage3);

        System.out.println("Decrypted messages:");
        System.out.println(decrypt(encryptedMessage1, secretKey));
        System.out.println(decrypt(encryptedMessage2, secretKey));
        System.out.println(decrypt(encryptedMessage3, secretKey));
    }
}