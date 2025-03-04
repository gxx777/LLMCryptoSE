import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESKeyReuse4 {
    private SecretKey secretKey;

    public AESKeyReuse4() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            secretKey = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public String encryptMessage(String message, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedMessage = cipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encryptedMessage);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    public String decryptMessage(String encryptedMessage, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decryptedMessage = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            return new String(decryptedMessage);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        AESKeyReuse4 aesKeyReuse4 = new AESKeyReuse4();

        SecretKey key1 = aesKeyReuse4.secretKey;
        SecretKey key2 = aesKeyReuse4.secretKey;
        SecretKey key3 = aesKeyReuse4.secretKey;

        String message1 = "Hello Participant 1!";
        String message2 = "Hello Participant 2!";
        String message3 = "Hello Participant 3!";

        String encryptedMessage1 = aesKeyReuse4.encryptMessage(message1, key1);
        String encryptedMessage2 = aesKeyReuse4.encryptMessage(message2, key2);
        String encryptedMessage3 = aesKeyReuse4.encryptMessage(message3, key3);

        System.out.println("Encrypted Message 1: " + encryptedMessage1);
        System.out.println("Decrypted Message 1: " + aesKeyReuse4.decryptMessage(encryptedMessage1, key1));

        System.out.println("Encrypted Message 2: " + encryptedMessage2);
        System.out.println("Decrypted Message 2: " + aesKeyReuse4.decryptMessage(encryptedMessage2, key2));

        System.out.println("Encrypted Message 3: " + encryptedMessage3);
        System.out.println("Decrypted Message 3: " + aesKeyReuse4.decryptMessage(encryptedMessage3, key3));
    }
}