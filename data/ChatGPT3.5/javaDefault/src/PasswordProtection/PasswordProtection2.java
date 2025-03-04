import java.util.HashMap;
import java.util.Map;

public class PasswordProtection2 {
    
    private Map<String, String> passwordMap;
    
    public PasswordProtection2() {
        passwordMap = new HashMap<>();
    }
    
    public boolean savePassword(String username, String password) {
        // Check if username already exists
        if (passwordMap.containsKey(username)) {
            System.out.println("Username already exists. Please choose a different username.");
            return false;
        }
        
        // Store the password securely
        passwordMap.put(username, password);
        System.out.println("Password saved successfully for username: " + username);
        
        return true;
    }
    
    public boolean validatePassword(String username, String password) {
        // Check if username exists
        if (!passwordMap.containsKey(username)) {
            System.out.println("Username does not exist.");
            return false;
        }
        
        // Validate the password
        if (password.equals(passwordMap.get(username))) {
            System.out.println("Password is correct for username: " + username);
            return true;
        } else {
            System.out.println("Incorrect password for username: " + username);
            return false;
        }
    }
    
}