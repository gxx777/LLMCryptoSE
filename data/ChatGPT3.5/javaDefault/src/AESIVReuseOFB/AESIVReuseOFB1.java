import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseOFB1 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/OFB/PKCS5Padding";
    private static final int KEY_SIZE = 16;

    private static Key generateKey() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] keyData = new byte[KEY_SIZE];
        random.nextBytes(keyData);
        return new SecretKeySpec(keyData, ALGORITHM);
    }

    public static String encrypt(String message, byte[] iv, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] encrypted = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedMessage, byte[] iv, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decrypted);
    }

    public static void main(String[] args) {
        try {
            // Generate key and IV
            Key key = generateKey();
            byte[] iv1 = new byte[16];
            byte[] iv2 = new byte[16];
            byte[] iv3 = new byte[16];

            // Sender 1 encrypts message
            String message1 = "Hello from sender 1";
            String encryptedMessage1 = encrypt(message1, iv1, key);
            System.out.println("Sender 1 sends encrypted message: " + encryptedMessage1);

            // Sender 2 encrypts message
            String message2 = "Hello from sender 2";
            String encryptedMessage2 = encrypt(message2, iv2, key);
            System.out.println("Sender 2 sends encrypted message: " + encryptedMessage2);

            // Sender 3 encrypts message
            String message3 = "Hello from sender 3";
            String encryptedMessage3 = encrypt(message3, iv3, key);
            System.out.println("Sender 3 sends encrypted message: " + encryptedMessage3);

            // Receivers decrypt messages
            String decryptedMessage1 = decrypt(encryptedMessage1, iv1, key);
            String decryptedMessage2 = decrypt(encryptedMessage2, iv2, key);
            String decryptedMessage3 = decrypt(encryptedMessage3, iv3, key);

            System.out.println("Receiver 1 decrypts message: " + decryptedMessage1);
            System.out.println("Receiver 2 decrypts message: " + decryptedMessage2);
            System.out.println("Receiver 3 decrypts message: " + decryptedMessage3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}