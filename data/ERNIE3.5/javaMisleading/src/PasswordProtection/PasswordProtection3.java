import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

public class PasswordProtection3 {
    private static final String HASH_ALGORITHM = "SHA-256";

    private String hashedPassword;

    public PasswordProtection3(String password) {
        this.hashedPassword = hashPassword(password);
    }

    public boolean verifyPassword(String password) {
        return Objects.equals(hashPassword(password), hashedPassword);
    }

    private String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
            byte[] hash = digest.digest(password.getBytes());
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hashing algorithm not found", e);
        }
    }

    private String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Example usage
    public static void main(String[] args) {
        PasswordProtection3 passwordProtection = new PasswordProtection3("my_secret_password");

        System.out.println(passwordProtection.verifyPassword("my_secret_password"));  // Should print true
        System.out.println(passwordProtection.verifyPassword("wrong_password"));       // Should print false
    }
}