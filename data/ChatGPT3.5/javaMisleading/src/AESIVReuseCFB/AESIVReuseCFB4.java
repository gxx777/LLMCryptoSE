import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCFB4 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CFB/PKCS5Padding";
    private static final String CHARSET = "UTF-8";

    public static String encrypt(String key, String initVector, String message) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(CHARSET));
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(CHARSET), ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            byte[] encrypted = cipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String key, String initVector, String encryptedMessage) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(CHARSET));
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(CHARSET), ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            return new String(decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        String key1 = "AESKey1";
        String key2 = "AESKey2";
        String key3 = "AESKey3";

        String initVector1 = "InitVec1";
        String initVector2 = "InitVec2";
        String initVector3 = "InitVec3";

        String message1 = "Message for participant 1";
        String message2 = "Message for participant 2";
        String message3 = "Message for participant 3";

        String encryptedMessage1 = encrypt(key1, initVector1, message1);
        String encryptedMessage2 = encrypt(key2, initVector2, message2);
        String encryptedMessage3 = encrypt(key3, initVector3, message3);

        System.out.println("Encrypted message for participant 1: " + encryptedMessage1);
        System.out.println("Decrypted message for participant 1: " + decrypt(key1, initVector1, encryptedMessage1));

        System.out.println("Encrypted message for participant 2: " + encryptedMessage2);
        System.out.println("Decrypted message for participant 2: " + decrypt(key2, initVector2, encryptedMessage2));

        System.out.println("Encrypted message for participant 3: " + encryptedMessage3);
        System.out.println("Decrypted message for participant 3: " + decrypt(key3, initVector3, encryptedMessage3));
    }
}