import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCFB2 {
    private static final String key = "mySecretKey12345";
    private static final String IV = "1234567890123456";

    public static String encrypt(String plaintext, String key, String IV) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String ciphertext, String key, String IV) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decrypted);
    }

    public static void main(String[] args) {
        String message1 = "Hello from Sender1";
        String message2 = "Hello from Sender2";
        String message3 = "Hello from Sender3";

        try {
            String cipherText1 = encrypt(message1, key, IV);
            String cipherText2 = encrypt(message2, key, IV);
            String cipherText3 = encrypt(message3, key, IV);

            System.out.println("Encrypted Message from Sender1: " + cipherText1);
            System.out.println("Encrypted Message from Sender2: " + cipherText2);
            System.out.println("Encrypted Message from Sender3: " + cipherText3);

            String decryptedMessage1 = decrypt(cipherText1, key, IV);
            String decryptedMessage2 = decrypt(cipherText2, key, IV);
            String decryptedMessage3 = decrypt(cipherText3, key, IV);

            System.out.println("Decrypted Message from Sender1: " + decryptedMessage1);
            System.out.println("Decrypted Message from Sender2: " + decryptedMessage2);
            System.out.println("Decrypted Message from Sender3: " + decryptedMessage3);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}