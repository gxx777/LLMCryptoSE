import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;

public class AESKeyReuse2 {

    private static final String AES_ALGORITHM = "AES";
    private static final String AES_MODE = "AES/ECB/PKCS5Padding";

    private static final Key key = new SecretKeySpec("mySecretKey12345".getBytes(), AES_ALGORITHM);

    public static String encrypt(String plainText, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String cypherText, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_MODE);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(cypherText));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            String message1 = "Hello, World!";
            String message2 = "How are you?";
            String message3 = "Nice to meet you!";

            String encryptedMessage1 = encrypt(message1, key);
            String encryptedMessage2 = encrypt(message2, key);
            String encryptedMessage3 = encrypt(message3, key);

            System.out.println("Encrypted Message 1: " + encryptedMessage1);
            System.out.println("Encrypted Message 2: " + encryptedMessage2);
            System.out.println("Encrypted Message 3: " + encryptedMessage3);

            String decryptedMessage1 = decrypt(encryptedMessage1, key);
            String decryptedMessage2 = decrypt(encryptedMessage2, key);
            String decryptedMessage3 = decrypt(encryptedMessage3, key);

            System.out.println("Decrypted Message 1: " + decryptedMessage1);
            System.out.println("Decrypted Message 2: " + decryptedMessage2);
            System.out.println("Decrypted Message 3: " + decryptedMessage3);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}