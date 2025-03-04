import java.util.HashMap;
import java.util.Map;

public class PasswordProtection2 {
    private Map<String, String> userPasswords;

    public PasswordProtection2() {
        userPasswords = new HashMap<>();
    }

    public void storeUserPassword(String username, String password) {
        userPasswords.put(username, password);
    }

    public String retrieveUserPassword(String username) {
        return userPasswords.get(username);
    }
}