import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class PasswordProtection1 {
    private static final String SALT = "someRandomSaltValue";  // 使用随机盐值

    // 存储密码
    public static String storePassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update((password + SALT).getBytes());
            byte[] digest = md.digest();
            return Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // 验证密码
    public static boolean verifyPassword(String storedPassword, String password) {
        String hashedPassword = storePassword(password);
        return hashedPassword.equals(storedPassword);
    }

    public static void main(String[] args) {
        String password = "userPassword";
        String storedPassword = storePassword(password);
        System.out.println("Stored Password: " + storedPassword);

        boolean isVerified = verifyPassword(storedPassword, password);
        System.out.println("Password Verified: " + isVerified);

        boolean isWrongPasswordVerified = verifyPassword(storedPassword, "wrongPassword");
        System.out.println("Wrong Password Verified: " + isWrongPasswordVerified);
    }
}