import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCBC1 {

    private static final String AES_CIPHER = "AES/CBC/PKCS5Padding";

    private static final byte[] secretKey1 = "secretKey1234567".getBytes();
    private static final byte[] secretKey2 = "abcdefgh12345678".getBytes();
    private static final byte[] secretKey3 = "password12345678".getBytes();

    public static String encrypt(String input, SecretKeySpec secretKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] encrypted = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encrypted, SecretKeySpec secretKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encrypted));
        return new String(decrypted);
    }

    public static void main(String[] args) {
        try {
            IvParameterSpec iv1 = new IvParameterSpec("initialVector12".getBytes());
            IvParameterSpec iv2 = new IvParameterSpec("abcd123456789012".getBytes());
            IvParameterSpec iv3 = new IvParameterSpec("9876543210zyxwv".getBytes());

            SecretKeySpec keySpec1 = new SecretKeySpec(secretKey1, "AES");
            SecretKeySpec keySpec2 = new SecretKeySpec(secretKey2, "AES");
            SecretKeySpec keySpec3 = new SecretKeySpec(secretKey3, "AES");

            String message1 = "Hello from Party 1";
            String message2 = "Greetings from Party 2";
            String message3 = "Welcome from Party 3";

            String encryptedMessage1 = encrypt(message1, keySpec1, iv1);
            String encryptedMessage2 = encrypt(message2, keySpec2, iv2);
            String encryptedMessage3 = encrypt(message3, keySpec3, iv3);

            System.out.println("Encrypted Message 1: " + encryptedMessage1);
            System.out.println("Encrypted Message 2: " + encryptedMessage2);
            System.out.println("Encrypted Message 3: " + encryptedMessage3);

            String decryptedMessage1 = decrypt(encryptedMessage1, keySpec1, iv1);
            String decryptedMessage2 = decrypt(encryptedMessage2, keySpec2, iv2);
            String decryptedMessage3 = decrypt(encryptedMessage3, keySpec3, iv3);

            System.out.println("Decrypted Message 1: " + decryptedMessage1);
            System.out.println("Decrypted Message 2: " + decryptedMessage2);
            System.out.println("Decrypted Message 3: " + decryptedMessage3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}