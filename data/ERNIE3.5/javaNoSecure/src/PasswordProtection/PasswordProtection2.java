import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class PasswordProtection2 {
    private Map<String, String> passwordMap;

    public PasswordProtection2() {
        this.passwordMap = new HashMap<>();
    }

    /**
     * 存储用户口令
     *
     * @param username 用户名
     * @param password 明文密码
     */
    public void storePassword(String username, String password) {
        try {
            // 使用SHA-256加密算法对密码进行哈希处理
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            passwordMap.put(username, hexString.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * 验证用户口令
     *
     * @param username 用户名
     * @param password 明文密码
     * @return 如果密码正确则返回true，否则返回false
     */
    public boolean verifyPassword(String username, String password) {
        String storedHash = passwordMap.get(username);
        if (storedHash == null) {
            return false;
        }
        try {
            // 使用SHA-256加密算法对密码进行哈希处理
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString().equals(storedHash);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return false;
        }
    }
}