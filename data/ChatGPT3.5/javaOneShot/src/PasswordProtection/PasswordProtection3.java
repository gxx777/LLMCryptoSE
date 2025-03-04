import java.security.MessageDigest;
import java.security.SecureRandom;

public class PasswordProtection3 {
    private byte[] encryptedPassword;

    public PasswordProtection3(String password) {
        byte[] passwordBytes = password.getBytes();
        // Encrypt password using a secure encryption algorithm
        encryptedPassword = encryptPassword(passwordBytes);
    }

    private byte[] encryptPassword(byte[] password) {
        // Implement secure encryption algorithm here
        return password; // Placeholder for encryption process
    }

    public boolean checkPassword(String password) {
        byte[] passwordBytes = password.getBytes();
        byte[] encryptedInput = encryptPassword(passwordBytes);

        // Compare encrypted input with stored encrypted password
        return MessageDigest.isEqual(encryptedPassword, encryptedInput);
    }
    
    public static void main(String[] args) {
        PasswordProtection3 passwordProtection = new PasswordProtection3("securePassword123");

        // Check if password is correct
        System.out.println("Password is correct: " + passwordProtection.checkPassword("securePassword123"));
        System.out.println("Password is correct: " + passwordProtection.checkPassword("incorrectPassword"));
    }
}