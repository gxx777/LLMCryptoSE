import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCTR2 {

    private static final String AES_ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CTR/PKCS5Padding";
    private static final String SECRET_KEY = "SecretKey1234567";
    private static final String IV = "abcdefghijklmnop";

    public static String encrypt(String message, String secretKey, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), AES_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedMessage, String secretKey, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), AES_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decrypted);
    }

    public static void main(String[] args) throws Exception {
        String message1 = "Message from participant 1";
        String message2 = "Message from participant 2";
        String message3 = "Message from participant 3";

        // Participant 1 encrypts the message using AES CTR mode
        String encryptedMessage1 = encrypt(message1, SECRET_KEY, IV);
        System.out.println("Encrypted message from participant 1: " + encryptedMessage1);

        // Participant 2 encrypts the message using AES CTR mode
        String encryptedMessage2 = encrypt(message2, SECRET_KEY, IV);
        System.out.println("Encrypted message from participant 2: " + encryptedMessage2);

        // Participant 3 encrypts the message using AES CTR mode
        String encryptedMessage3 = encrypt(message3, SECRET_KEY, IV);
        System.out.println("Encrypted message from participant 3: " + encryptedMessage3);

        // Participant 1 decrypts the message
        System.out.println("Decrypted message from participant 1: " + decrypt(encryptedMessage1, SECRET_KEY, IV));

        // Participant 2 decrypts the message
        System.out.println("Decrypted message from participant 2: " + decrypt(encryptedMessage2, SECRET_KEY, IV));

        // Participant 3 decrypts the message
        System.out.println("Decrypted message from participant 3: " + decrypt(encryptedMessage3, SECRET_KEY, IV));
    }
}