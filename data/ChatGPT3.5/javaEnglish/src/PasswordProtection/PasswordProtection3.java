import java.util.HashMap;
import java.util.Map;

public class PasswordProtection3 {
    private Map<String, String> passwordMap;

    public PasswordProtection3() {
        passwordMap = new HashMap<>();
    }

    public void storePassword(String username, String password) {
        passwordMap.put(username, password);
    }

    public String retrievePassword(String username) {
        return passwordMap.get(username);
    }

    public static void main(String[] args) {
        PasswordProtection3 passwordProtection = new PasswordProtection3();

        // Storing passwords
        passwordProtection.storePassword("user1", "password123");
        passwordProtection.storePassword("user2", "securePassword456");

        // Retrieving passwords
        String password1 = passwordProtection.retrievePassword("user1");
        String password2 = passwordProtection.retrievePassword("user2");

        System.out.println("Password for user1: " + password1);
        System.out.println("Password for user2: " + password2);
    }
}