import java.util.HashMap;
import java.util.Map;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

public class PasswordProtection1 {
    private Map<String, String> userPasswords;

    public PasswordProtection1() {
        userPasswords = new HashMap<>();
    }

    public void storeUserPassword(String username, String password) {
        String hashedPassword = hashPassword(password);
        userPasswords.put(username, hashedPassword);
    }

    public boolean checkUserPassword(String username, String password) {
        String hashedPassword = hashPassword(password);
        String storedPassword = userPasswords.get(username);
        return storedPassword != null && storedPassword.equals(hashedPassword);
    }

    private String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }
}