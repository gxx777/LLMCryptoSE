import java.util.HashMap;
import java.util.Map;

public class PasswordProtection4 {
    
    private Map<String, String> passwords;
    
    public PasswordProtection4() {
        passwords = new HashMap<>();
    }
    
    public void setPassword(String username, String password) {
        // 这里可以加入一些安全性检查，比如密码长度、是否包含特殊字符等
        passwords.put(username, password);
    }
    
    public String getPassword(String username) {
        if (passwords.containsKey(username)) {
            return passwords.get(username);
        } else {
            return null;
        }
    }
    
    public static void main(String[] args) {
        PasswordProtection4 passwordProtection = new PasswordProtection4();
        
        passwordProtection.setPassword("admin", "adminPassword");
        
        String password = passwordProtection.getPassword("admin");
        System.out.println("Password for admin is: " + password);
    }
}