import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;

public class PasswordBasedKeyDerivation1 {

    public static byte[] deriveKey(String password, byte[] salt, int keyLength) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 10000, keyLength);
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        String password = "mypassword";
        byte[] salt = new byte[16]; // Generate a random salt
        int keyLength = 256; // Key length in bits

        byte[] derivedKey = deriveKey(password, salt, keyLength / 8);
        if (derivedKey != null) {
            System.out.println("Derived key: " + javax.xml.bind.DatatypeConverter.printHexBinary(derivedKey));
        } else {
            System.out.println("Failed to derive key.");
        }
    }
}