import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCBC3 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

    private static final String SECRET_KEY = "ThisIsASecretKey";
    private static final String IV = "ThisIsAnIV12345";

    public static String encrypt(String message, String secretKey, String iv) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
            byte[] encryptedBytes = cipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String encryptedMessage, String secretKey, String iv) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        String message1 = "Hello from Participant 1";
        String message2 = "Hello from Participant 2";
        String message3 = "Hello from Participant 3";

        String encryptedMessage1 = encrypt(message1, SECRET_KEY, IV);
        String encryptedMessage2 = encrypt(message2, SECRET_KEY, IV);
        String encryptedMessage3 = encrypt(message3, SECRET_KEY, IV);

        System.out.println("Encrypted message from Participant 1: " + encryptedMessage1);
        System.out.println("Decrypted message from Participant 1: " + decrypt(encryptedMessage1, SECRET_KEY, IV));

        System.out.println("Encrypted message from Participant 2: " + encryptedMessage2);
        System.out.println("Decrypted message from Participant 2: " + decrypt(encryptedMessage2, SECRET_KEY, IV));

        System.out.println("Encrypted message from Participant 3: " + encryptedMessage3);
        System.out.println("Decrypted message from Participant 3: " + decrypt(encryptedMessage3, SECRET_KEY, IV));
    }
}