import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class PasswordProtection1 {
    private static final String SALT = "your_secret_salt"; // Replace with a unique salt value

    public static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update((password + SALT).getBytes());
            byte[] digest = md.digest();
            return Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to hash password", e);
        }
    }

    public static boolean verifyPassword(String password, String hashedPassword) {
        String hashedInputPassword = hashPassword(password);
        return hashedInputPassword.equals(hashedPassword);
    }

    public static void main(String[] args) {
        // Example usage
        String userPassword = "my_password123";
        String hashedPassword = hashPassword(userPassword);
        System.out.println("Hashed Password: " + hashedPassword);

        boolean isPasswordValid = verifyPassword(userPassword, hashedPassword);
        System.out.println("Password Valid: " + isPasswordValid);
    }
}