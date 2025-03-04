import java.util.HashMap;
import java.util.Map;

public class PasswordProtection2 {
    private Map<String, String> passwords;

    public PasswordProtection2() {
        passwords = new HashMap<>();
    }

    public void storePassword(String username, String password) {
        passwords.put(username, password);
    }

    public String retrievePassword(String username) {
        return passwords.get(username);
    }
}