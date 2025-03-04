import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class PasswordBasedKeyDerivation1 {

    private static final int ITERATION_COUNT = 10000;
    private static final int KEY_LENGTH = 256;

    public static void main(String[] args) {
        String password = "your_password_here";
        String salt = "your_salt_here";

        try {
            byte[] derivedKey = deriveKey(password, salt);
            System.out.println("Derived key: " + Base64.getEncoder().encodeToString(derivedKey));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    private static byte[] deriveKey(String password, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), ITERATION_COUNT, KEY_LENGTH);
        return factory.generateSecret(spec).getEncoded();
    }
}