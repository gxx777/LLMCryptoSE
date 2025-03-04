import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class PasswordProtection2 {
    private String salt; // 用于增加密码的复杂性
    private String hashedPassword; // 存储加密后的密码

    public PasswordProtection2(String salt) {
        this.salt = salt;
    }

    public void setPassword(String password) throws NoSuchAlgorithmException {
        // 使用SHA-256算法进行哈希
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // 添加盐值到密码
        String saltedPassword = password + salt;

        // 计算哈希值
        byte[] hash = md.digest(saltedPassword.getBytes());

        // 使用Base64编码以便于存储
        this.hashedPassword = Base64.getEncoder().encodeToString(hash);
    }

    public boolean verifyPassword(String password) throws NoSuchAlgorithmException {
        // 使用相同的盐值和密码进行哈希
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String saltedPassword = password + salt;
        byte[] hash = md.digest(saltedPassword.getBytes());

        // 使用Base64编码以便于比较
        String newHash = Base64.getEncoder().encodeToString(hash);

        // 比较哈希值
        return this.hashedPassword.equals(newHash);
    }
}