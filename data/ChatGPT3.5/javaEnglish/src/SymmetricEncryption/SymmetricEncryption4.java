import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

public class SymmetricEncryption4 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES";

    private static Key secretKey = new SecretKeySpec("1234567890123456".getBytes(), ALGORITHM);

    public static String encrypt(String strToEncrypt) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(strToEncrypt.getBytes());
            return new String(encryptedBytes);
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String decrypt(String strToDecrypt) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = cipher.doFinal(strToDecrypt.getBytes());
            return new String(decryptedBytes);
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    public static void main(String[] args) {
        String strToEncrypt = "Hello, World!";
        String encryptedString = encrypt(strToEncrypt);
        System.out.println("Encrypted String: " + encryptedString);

        String decryptedString = decrypt(encryptedString);
        System.out.println("Decrypted String: " + decryptedString);
    }
}