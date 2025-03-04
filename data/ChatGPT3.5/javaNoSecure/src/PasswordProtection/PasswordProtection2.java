import java.util.HashMap;

public class PasswordProtection2 {
    
    private HashMap<String, String> passwordMap;

    public PasswordProtection2() {
        passwordMap = new HashMap<>();
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

    public void deletePassword(String username) {
        if (passwordMap.containsKey(username)) {
            passwordMap.remove(username);
            System.out.println("Password deleted successfully for user: " + username);
        } else {
            System.out.println("Password not found for user: " + username);
        }
    }

    public void updatePassword(String username, String newPassword) {
        if (passwordMap.containsKey(username)) {
            passwordMap.put(username, newPassword);
            System.out.println("Password updated successfully for user: " + username);
        } else {
            System.out.println("Password not found for user: " + username);
        }
    }
}