import java.util.HashMap;

public class PasswordProtection3 {
    private HashMap<String, String> passwordMap;

    public PasswordProtection3() {
        this.passwordMap = new HashMap<>();
    }

    public void storePassword(String username, String password) {
        if (username != null && !username.isEmpty() && password != null && !password.isEmpty()) {
            passwordMap.put(username, password);
            System.out.println("Password stored successfully for user " + username);
        } else {
            System.out.println("Invalid username or password. Please try again.");
        }
    }

    public String retrievePassword(String username) {
        if (passwordMap.containsKey(username)) {
            return passwordMap.get(username);
        } else {
            System.out.println("User " + username + " does not exist in the system.");
            return null;
        }
    }

    public static void main(String[] args) {
        PasswordProtection3 passwordProtection = new PasswordProtection3();
        passwordProtection.storePassword("john_doe", "password123");
        passwordProtection.storePassword("jane_smith", "abcdef");
        
        System.out.println("Retrieving password for john_doe: " + passwordProtection.retrievePassword("john_doe"));
        System.out.println("Retrieving password for alice_wonderland: " + passwordProtection.retrievePassword("alice_wonderland"));
    }
}