import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class PasswordBasedKeyDerivation4 {
    
    public static byte[] deriveKey(String password, byte[] salt, int keyLength, int iterationCount) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength * 8);
            return factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    public static void main(String[] args) {
        String password = "mySecretPassword";
        byte[] salt = {1, 2, 3, 4, 5, 6, 7, 8}; // This should be randomly generated
        int keyLength = 16; // Key length in bytes
        int iterationCount = 10000; // Number of iterations
        
        byte[] derivedKey = deriveKey(password, salt, keyLength, iterationCount);
        
        System.out.println("Derived Key: " + bytesToHex(derivedKey));
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }
}