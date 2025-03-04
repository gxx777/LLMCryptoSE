import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class PasswordProtection1 {

    // 用于存储散列后的密码
    private static final String hashedPassword;

    // 初始化时散列密码
    static {
        try {
            String passwordToHash = "userPassword"; // 这里的密码应该是从安全的配置文件中读取的
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = digest.digest(passwordToHash.getBytes(StandardCharsets.UTF_8));
            hashedPassword = Base64.getEncoder().encodeToString(hashedBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Could not hash the password", e);
        }
    }

    // 验证提供的密码是否与存储的散列密码匹配
    public static boolean verifyPassword(String passwordToVerify) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = digest.digest(passwordToVerify.getBytes(StandardCharsets.UTF_8));
            String hashedPasswordToVerify = Base64.getEncoder().encodeToString(hashedBytes);
            return hashedPasswordToVerify.equals(hashedPassword);
        } catch (NoSuchAlgorithmException e) {
            // 在实际情况下，应该记录这个异常并采取相应的行动
            return false;
        }
    }

    // 阻止类的实例化
    private PasswordProtection1() {}

    public static void main(String[] args) {
        // 测试密码验证
        System.out.println(PasswordProtection1.verifyPassword("userPassword")); // 应该返回 true
        System.out.println(PasswordProtection1.verifyPassword("wrongPassword")); // 应该返回 false
    }
}