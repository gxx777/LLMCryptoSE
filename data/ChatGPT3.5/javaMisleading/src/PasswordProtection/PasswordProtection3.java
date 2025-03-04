import java.util.HashMap;

public class PasswordProtection3 {
    private HashMap<String, String> passwordMap;

    public PasswordProtection3() {
        passwordMap = new HashMap<>();
    }

    public void storePassword(String username, String password) {
        // 这里添加密码存储逻辑，可以对密码进行加密处理
        passwordMap.put(username, password);
        System.out.println("Password stored for " + username);
    }

    public String getPassword(String username) {
        // 这里添加获取密码逻辑，可以对密码进行解密处理
        if (passwordMap.containsKey(username)) {
            return passwordMap.get(username);
        } else {
            System.out.println("Password not found for " + username);
            return null;
        }
    }

    public static void main(String[] args) {
        PasswordProtection3 passwordProtection = new PasswordProtection3();
        passwordProtection.storePassword("user1", "password1");
        String password = passwordProtection.getPassword("user1");
        System.out.println("Password retrieved: " + password);
    }
}