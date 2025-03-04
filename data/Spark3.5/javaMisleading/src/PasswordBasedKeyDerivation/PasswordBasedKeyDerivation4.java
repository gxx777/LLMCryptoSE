import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.security.spec.KeySpec;

public class PasswordBasedKeyDerivation4 {
    private static final int ITERATIONS = 1000; // 可以根据实际情况调整迭代次数
    private static final int KEY_LENGTH = 256; // 密钥长度，可以根据需要调整

    public static String deriveKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] derivedKey = skf.generateSecret(spec).getEncoded();
        return Base64.getEncoder().encodeToString(derivedKey);
    }
}