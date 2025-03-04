import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class PasswordProtection4 {
    
    private Map<String, String> passwordMap;

    public PasswordProtection4() {
        this.passwordMap = new HashMap<>();
    }

    public void savePassword(String username, String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashedPassword = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hashedPassword) {
                sb.append(String.format("%02x", b));
            }
            passwordMap.put(username, sb.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public boolean verifyPassword(String username, String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashedPassword = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hashedPassword) {
                sb.append(String.format("%02x", b));
            }
            String storedPassword = passwordMap.get(username);
            return sb.toString().equals(storedPassword);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) {
        PasswordProtection4 passwordProtection = new PasswordProtection4();
        passwordProtection.savePassword("user1", "password123");

        System.out.println(passwordProtection.verifyPassword("user1", "password123")); // true
        System.out.println(passwordProtection.verifyPassword("user1", "password456")); // false
    }
}