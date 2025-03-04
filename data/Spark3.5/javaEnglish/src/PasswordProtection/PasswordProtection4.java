import java.util.HashMap;

public class PasswordProtection4 {
    private HashMap<String, String> passwordStore;

    public PasswordProtection4() {
        passwordStore = new HashMap<>();
    }

    public void storePassword(String username, String password) {
        passwordStore.put(username, password);
    }

    public String retrievePassword(String username) {
        return passwordStore.get(username);
    }
}