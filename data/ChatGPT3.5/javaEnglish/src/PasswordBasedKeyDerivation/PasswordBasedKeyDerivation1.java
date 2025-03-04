import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class PasswordBasedKeyDerivation1 {

    public static byte[] deriveKeyFromPassword(char[] password, byte[] salt, int iterations, int keyLength) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
            return factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        char[] password = "mySecurePassword".toCharArray();
        byte[] salt = { 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, (byte) 0x8b};
        int iterations = 10000;
        int keyLength = 256;

        byte[] derivedKey = deriveKeyFromPassword(password, salt, iterations, keyLength);
        if (derivedKey != null) {
            System.out.println("Derived key: " + javax.xml.bind.DatatypeConverter.printHexBinary(derivedKey));
        }
    }
}