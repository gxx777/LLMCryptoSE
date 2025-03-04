import java.util.HashMap;
import java.util.Map;

public class PasswordProtection4 {

    private Map<String, String> passwords;

    public PasswordProtection4() {
        passwords = new HashMap<>();
    }

    public void storePassword(String username, String password) {
        // 这里可以添加校验逻辑以确保密码安全性
        passwords.put(username, password);
    }

    public String getPassword(String username) {
        return passwords.get(username);
    }

    public static void main(String[] args) {
        PasswordProtection4 passwordProtection4 = new PasswordProtection4();
        passwordProtection4.storePassword("user1", "password1");
        passwordProtection4.storePassword("user2", "password2");

        System.out.println("Password for user1: " + passwordProtection4.getPassword("user1"));
        System.out.println("Password for user2: " + passwordProtection4.getPassword("user2"));
    }
}