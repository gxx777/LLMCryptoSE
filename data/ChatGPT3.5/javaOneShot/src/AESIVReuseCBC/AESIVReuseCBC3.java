import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCBC3 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    private SecretKey secretKey1, secretKey2, secretKey3;
    private IvParameterSpec iv1, iv2, iv3;

    public AESIVReuseCBC3() {
        try {
            // Generate unique secret keys
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(256);
            secretKey1 = keyGenerator.generateKey();
            secretKey2 = keyGenerator.generateKey();
            secretKey3 = keyGenerator.generateKey();

            // Generate unique IVs
            iv1 = generateIV();
            iv2 = generateIV();
            iv3 = generateIV();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String encrypt(String message, SecretKey secretKey, IvParameterSpec iv) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            byte[] encryptedBytes = cipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String decrypt(String encryptedMessage, SecretKey secretKey, IvParameterSpec iv) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            byte[] cipherText = Base64.getDecoder().decode(encryptedMessage);
            byte[] decryptedBytes = cipher.doFinal(cipherText);
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private IvParameterSpec generateIV() {
        byte[] iv = new byte[16];
        // Generate random IV
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public String sendMessageToParticipant1(String message) {
        return encrypt(message, secretKey1, iv1);
    }

    public String sendMessageToParticipant2(String message) {
        return encrypt(message, secretKey2, iv2);
    }

    public String sendMessageToParticipant3(String message) {
        return encrypt(message, secretKey3, iv3);
    }

    public String receiveMessageFromParticipant1(String encryptedMessage) {
        return decrypt(encryptedMessage, secretKey1, iv1);
    }

    public String receiveMessageFromParticipant2(String encryptedMessage) {
        return decrypt(encryptedMessage, secretKey2, iv2);
    }

    public String receiveMessageFromParticipant3(String encryptedMessage) {
        return decrypt(encryptedMessage, secretKey3, iv3);
    }
}