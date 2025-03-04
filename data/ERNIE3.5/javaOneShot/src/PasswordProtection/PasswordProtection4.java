import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class PasswordProtection4 {

    private Map<String, String> userPasswords;
    private Map<String, Integer> failedAttempts;
    private static final int MAX_FAILED_ATTEMPTS = 3;
    private static final int LOCK_TIME_MINUTES = 5;

    public PasswordProtection4() {
        userPasswords = new HashMap<>();
        failedAttempts = new HashMap<>();
    }

    // 添加用户和密码
    public void addUser(String username, String password) {
        if (userPasswords.containsKey(username)) {
            throw new IllegalArgumentException("Username already exists");
        }
        // 生成盐值
        String salt = generateSalt();
        // 存储散列后的密码和盐值
        userPasswords.put(username, hashPassword(password, salt));
        failedAttempts.put(username, 0);
    }

    // 检查密码
    public boolean checkPassword(String username, String password) {
        Integer attempts = failedAttempts.get(username);
        if (attempts != null && attempts >= MAX_FAILED_ATTEMPTS) {
            // 账户已锁定
            return false;
        }
        String storedHash = userPasswords.get(username);
        if (storedHash == null) {
            return false;
        }
        // 提取盐值
        String salt = storedHash.split("\\$")[2];
        // 计算密码的散列值
        String hashedPassword = hashPassword(password, salt);
        // 比较散列值
        return hashedPassword.equals(storedHash);
    }

    // 散列密码和盐值
    private String hashPassword(String password, String salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update((password + salt).getBytes());
            byte[] hash = digest.digest();
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            // 返回格式为 "SHA-256$salt$hash"
            return "SHA-256$" + salt + "$" + hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }

    // 生成随机盐值
    private String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return new String(salt);
    }

    // 增加失败尝试次数
    public void increaseFailedAttempts(String username) {
        int attempts = failedAttempts.getOrDefault(username, 0) + 1;
        failedAttempts.put(username, attempts);
        if (attempts >= MAX_FAILED_ATTEMPTS) {
            // 锁定账户
            lockAccount(username);
        }
    }

    // 锁定账户
    private void lockAccount(String username) {
        // 可以在这里添加逻辑来锁定账户，例如禁用账户或设置锁定时间
    }

}
