import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

public class SymmetricEncryption3 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final byte[] KEY = "mySecretKey12345".getBytes();

    public static byte[] encrypt(String input) {
        try {
            Key secretKey = new SecretKeySpec(KEY, ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            return cipher.doFinal(input.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static String decrypt(byte[] input) {
        try {
            Key secretKey = new SecretKeySpec(KEY, ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            return new String(cipher.doFinal(input));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static void main(String[] args) {
        String originalString = "Hello, world!";
        byte[] encryptedString = encrypt(originalString);
        String decryptedString = decrypt(encryptedString);

        System.out.println("Original String: " + originalString);
        System.out.println("Encrypted String: " + new String(encryptedString));
        System.out.println("Decrypted String: " + decryptedString);
    }
}