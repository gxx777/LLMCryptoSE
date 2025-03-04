import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class PasswordProtection4 {
    private Map<String, String> passwordDatabase;

    public PasswordProtection4() {
        passwordDatabase = new HashMap<>();
    }

    public void storePassword(String username, String password) {
        String hashedPassword = hashPassword(password);
        passwordDatabase.put(username, hashedPassword);
    }

    public boolean verifyPassword(String username, String password) {
        String storedPassword = passwordDatabase.get(username);
        if (storedPassword == null) {
            return false;
        }
        String hashedPassword = hashPassword(password);
        return storedPassword.equals(hashedPassword);
    }

    private String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Could not hash password", e);
        }
    }
}