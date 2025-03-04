import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class PasswordProtection2 {
    private Map<String, String> passwordMap;

    public PasswordProtection2() {
        this.passwordMap = new HashMap<>();
    }

    public void setPassword(String username, String password) {
        String hashedPassword = hashPassword(password);
        passwordMap.put(username, hashedPassword);
    }

    public boolean checkPassword(String username, String password) {
        String hashedPassword = hashPassword(password);
        return passwordMap.containsKey(username) &&
                passwordMap.get(username).equals(hashedPassword);
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
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        PasswordProtection2 pp = new PasswordProtection2();
        pp.setPassword("user1", "password123");

        System.out.println("Checking password for user1: " + pp.checkPassword("user1", "password123")); // true
        System.out.println("Checking password for user2: " + pp.checkPassword("user2", "password123")); // false
    }
}