import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class PasswordBasedKeyDerivation2 {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA512";
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 256;

    public static byte[] deriveKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory f = SecretKeyFactory.getInstance(ALGORITHM);
        return f.generateSecret(new SecretKeySpec(password.getBytes(), ALGORITHM)).getEncoded();
    }

    public static String getBase64EncodedKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = deriveKey(password, salt);
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    public static void main(String[] args) {
        try {
            String password = "mySecurePassword";
            byte[] salt = new byte[16]; // 128-bit salt
            java.security.SecureRandom random = new java.security.SecureRandom();
            random.nextBytes(salt);

            byte[] keyBytes = deriveKey(password, salt);
            String base64Key = getBase64EncodedKey(password, salt);

            System.out.println("Derived Key (hex): " + bytesToHex(keyBytes));
            System.out.println("Derived Key (Base64): " + base64Key);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    private static String bytesToHex(byte[] hash) {
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}