import java.util.HashMap;

public class PasswordProtection4 {
    private HashMap<String, String> passwordMap;

    public PasswordProtection4() {
        passwordMap = new HashMap<>();
    }

    public void storePassword(String username, String password) {
        passwordMap.put(username, password);
        System.out.println("Password stored for user: " + username);
    }

    public String retrievePassword(String username) {
        String password = passwordMap.get(username);
        if (password != null) {
            System.out.println("Password retrieved for user: " + username);
            return password;
        } else {
            System.out.println("No password found for user: " + username);
            return null;
        }
    }

    public static void main(String[] args) {
        PasswordProtection4 passwordProtection = new PasswordProtection4();

        passwordProtection.storePassword("user1", "password1");
        passwordProtection.storePassword("user2", "password2");

        System.out.println("Retrieved password: " + passwordProtection.retrievePassword("user1"));
        System.out.println("Retrieved password: " + passwordProtection.retrievePassword("user3"));
    }
}