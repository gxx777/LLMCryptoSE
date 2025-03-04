import java.util.HashMap;

public class PasswordProtection4 {
    private HashMap<String, String> passwordMap;

    public PasswordProtection4() {
        this.passwordMap = new HashMap<>();
    }

    public void storePassword(String username, String password) {
        passwordMap.put(username, password);
        System.out.println("Password stored successfully for user: " + username);
    }

    public String getPassword(String username) {
        if (passwordMap.containsKey(username)) {
            return passwordMap.get(username);
        } else {
            System.out.println("Password not found for user: " + username);
            return null;
        }
    }

    public static void main(String[] args) {
        PasswordProtection4 passwordProtection = new PasswordProtection4();
        String username = "user123";
        String password = "password123";
      
        passwordProtection.storePassword(username, password);

        String retrievedPassword = passwordProtection.getPassword(username);
        if (retrievedPassword != null) {
            System.out.println("Retrieved password for user " + username + ": " + retrievedPassword);
        }
    }
}