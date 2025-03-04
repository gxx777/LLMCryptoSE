import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PasswordProtection3 {

    private static final String SALT = "YourRandomSaltString"; // 用于增加散列复杂性的盐值

    // 将密码散列并存储
    public static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update((password + SALT).getBytes(StandardCharsets.UTF_8));
            byte[] digest = md.digest();
            return bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // 验证提供的密码是否与存储的散列值匹配
    public static boolean verifyPassword(String storedHash, String password) {
        return storedHash.equals(hashPassword(password));
    }

    // 将字节数组[]转换为十六进制字符串
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    // 主方法，用于测试
    public static void main(String[] args) {
        String password = "mySecretPassword";
        String hashedPassword = hashPassword(password);
        System.out.println("Hashed Password: " + hashedPassword);

        boolean isVerified = verifyPassword(hashedPassword, password);
        System.out.println("Password Verified: " + isVerified);

        boolean isWrongPasswordVerified = verifyPassword(hashedPassword, "wrongPassword");
        System.out.println("Wrong Password Verified: " + isWrongPasswordVerified);
    }
}