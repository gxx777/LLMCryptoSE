import java.util.HashMap;

public class PasswordProtection2 {
    private HashMap<String, String> userPasswords;

    public PasswordProtection2() {
        userPasswords = new HashMap<>();
    }

    public void storePassword(String username, String password) {
        userPasswords.put(username, password);
    }

    public String retrievePassword(String username) {
        return userPasswords.get(username);
    }

    public static void main(String[] args) {
        PasswordProtection2 passwordProtection = new PasswordProtection2();

        // Storing passwords
        passwordProtection.storePassword("user1", "password123");
        passwordProtection.storePassword("user2", "pass456");

        // Retrieving passwords
        System.out.println("Password for user1: " + passwordProtection.retrievePassword("user1"));
        System.out.println("Password for user2: " + passwordProtection.retrievePassword("user2"));
    }
}