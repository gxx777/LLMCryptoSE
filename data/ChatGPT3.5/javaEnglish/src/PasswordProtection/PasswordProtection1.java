import java.util.HashMap;

public class PasswordProtection1 {
    private HashMap<String, String> passwords;

    public PasswordProtection1() {
        passwords = new HashMap<>();
    }

    public void storePassword(String username, String password) {
        // You can add encryption or hashing here for added security
        passwords.put(username, password);
    }

    public String retrievePassword(String username) {
        // You can add decryption or hashing here for added security
        return passwords.get(username);
    }

    public static void main(String[] args) {
        PasswordProtection1 passwordProtection = new PasswordProtection1();
        passwordProtection.storePassword("user1", "password123");
        
        String retrievedPassword = passwordProtection.retrievePassword("user1");
        System.out.println("Retrieved password: " + retrievedPassword);
    }
}