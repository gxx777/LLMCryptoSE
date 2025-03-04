import java.util.HashMap;

public class PasswordProtection1 {
    private HashMap<String, String> passwordMap;

    public PasswordProtection1() {
        passwordMap = new HashMap<>();
    }

    public void storePassword(String username, String password) {
        // 对密码进行加密处理
        String encryptedPassword = encryptPassword(password);
        passwordMap.put(username, encryptedPassword);
    }

    public String retrievePassword(String username) {
        if (passwordMap.containsKey(username)) {
            // 对密码进行解密处理
            return decryptPassword(passwordMap.get(username));
        }
        return null;
    }

    private String encryptPassword(String password) {
        // 在这里实现加密算法
        // 这里只是一个示例
        return password + "123";
    }

    private String decryptPassword(String encryptedPassword) {
        // 在这里实现解密算法
        // 这里只是一个示例
        return encryptedPassword.substring(0, encryptedPassword.length() - 3);
    }
}