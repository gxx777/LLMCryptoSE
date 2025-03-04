import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class PasswordProtection4 {
    private Map<String, String> users;

    public PasswordProtection4() {
        users = new HashMap<>();
    }

    public void addUser(String username, String password) {
        String hashedPassword = hashPassword(password);
        users.put(username, hashedPassword);
    }

    public boolean checkPassword(String username, String password) {
        String hashedPassword = hashPassword(password);
        return users.containsKey(username) && users.get(username).equals(hashedPassword);
    }

    private String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }
}