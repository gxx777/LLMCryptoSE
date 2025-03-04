import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SymmetricEncryptionCBC2 {

    private static final String AES_CIPHER = "AES/CBC/PKCS5Padding";
    private static final byte[] IV = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    private static final String SECRET_KEY = "abcdefghijklmnop"; // 16 characters secret key

    public static String encrypt(String input) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedInput) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedInput));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        String originalString = "Hello, world!";
        String encryptedString = SymmetricEncryptionCBC2.encrypt(originalString);
        String decryptedString = SymmetricEncryptionCBC2.decrypt(encryptedString);

        System.out.println("Original string: " + originalString);
        System.out.println("Encrypted string: " + encryptedString);
        System.out.println("Decrypted string: " + decryptedString);
    }
}