import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class PasswordProtection3 {
    private Map<String, String> passwordDatabase;

    public PasswordProtection3() {
        passwordDatabase = new HashMap<>();
    }

    public void storePassword(String username, String password) {
        try {
            // Encrypt the password using SHA-256
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            password = hexString.toString();

            // Store the encrypted password in the database
            passwordDatabase.put(username, password);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public String retrievePassword(String username) {
        return passwordDatabase.get(username);
    }

    public boolean validatePassword(String username, String password) {
        // Retrieve the stored encrypted password
        String storedPassword = retrievePassword(username);

        if (storedPassword == null) {
            return false; // User not found
        }

        try {
            // Encrypt the provided password using the same method
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            password = hexString.toString();

            // Compare the encrypted passwords
            return storedPassword.equals(password);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) {
        PasswordProtection3 passwordProtection = new PasswordProtection3();

        // Storing passwords
        passwordProtection.storePassword("user1", "mypassword123");
        passwordProtection.storePassword("user2", "securepassword456");

        // Validating passwords
        System.out.println(passwordProtection.validatePassword("user1", "mypassword123")); // true
        System.out.println(passwordProtection.validatePassword("user2", "insecurepassword456")); // false
    }
}