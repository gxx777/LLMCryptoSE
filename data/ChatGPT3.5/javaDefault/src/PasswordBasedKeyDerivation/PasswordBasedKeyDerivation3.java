import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class PasswordBasedKeyDerivation3 {

    private static final String SECRET_ALGORITHM = "PBKDF2WithHmacSHA256";

    public static byte[] deriveKey(char[] password, byte[] salt, int keyLength, int iterations) {

        KeySpec keySpec = new PBEKeySpec(password, salt, iterations, keyLength);

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_ALGORITHM);
            return factory.generateSecret(keySpec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        char[] password = "MySuperStrongPassword123!".toCharArray();
        byte[] salt = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        int keyLength = 256; // key length in bits
        int iterations = 10000;

        byte[] derivedKey = deriveKey(password, salt, keyLength, iterations);

        if (derivedKey != null) {
            System.out.println("Derived key: " + bytesToHex(derivedKey));
        }
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}