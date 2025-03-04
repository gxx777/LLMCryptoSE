import java.util.HashMap;

public class PasswordProtection4 {
    private HashMap<String, String> userPasswords;

    public PasswordProtection4() {
        userPasswords = new HashMap<>();
    }

    public void storeUserPassword(String username, String password) {
        userPasswords.put(username, password);
    }

    public String retrieveUserPassword(String username) {
        return userPasswords.get(username);
    }
}