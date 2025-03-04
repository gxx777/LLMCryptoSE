import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.xml.bind.DatatypeConverter;

public class SymmetricEncryption3 {

    public static String encrypt(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(input.getBytes());
            byte[] digest = md.digest();
            return DatatypeConverter.printHexBinary(digest).toUpperCase();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error: " + e.getMessage());
        }
    }

    public static String decrypt(String input) {
        // MD5 is a hash function, not an encryption algorithm, so it's not possible to decrypt the output
        throw new UnsupportedOperationException("MD5 is a hash function, not an encryption algorithm");
    }

    public static void main(String[] args) {
        String originalText = "Hello, World!";
        String encryptedText = encrypt(originalText);
        System.out.println("Original text: " + originalText);
        System.out.println("Encrypted text: " + encryptedText);

        // The following line will throw an UnsupportedOperationException
        // String decryptedText = decrypt(encryptedText);
    }
}