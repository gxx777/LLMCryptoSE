import java.util.HashMap;
import java.util.Map;

public class PasswordProtection1 {
    private Map<String, String> userPasswords;

    public PasswordProtection1() {
        userPasswords = new HashMap<>();
    }

    public void storeUserPassword(String username, String password) {
        userPasswords.put(username, password);
    }

    public String retrieveUserPassword(String username) {
        return userPasswords.get(username);
    }

    public static void main(String[] args) {
        PasswordProtection1 passwordProtection = new PasswordProtection1();
        passwordProtection.storeUserPassword("user1", "password1");
        passwordProtection.storeUserPassword("user2", "password2");

        System.out.println("User1's password: " + passwordProtection.retrieveUserPassword("user1"));
        System.out.println("User2's password: " + passwordProtection.retrieveUserPassword("user2"));
    }
}