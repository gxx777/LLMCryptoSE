import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class PasswordBasedKeyDerivation4 {
    private static final int ITERATION_COUNT = 65536;
    private static final int KEY_LENGTH = 128;
    private static final String ALGORITHM = "PBKDF2WithHmacSHA1";

    public static String deriveKey(String password, byte[] salt) {
        char[] passwordChars = password.toCharArray();
        KeySpec spec = new PBEKeySpec(passwordChars, salt, ITERATION_COUNT, KEY_LENGTH);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            byte[] secretKey = factory.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(secretKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Error while deriving key", e);
        } finally {
            ((PBEKeySpec) spec).clearPassword();
        }
    }
}