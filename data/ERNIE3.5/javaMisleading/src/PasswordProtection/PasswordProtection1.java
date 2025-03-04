import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

public class PasswordProtection1 {

    // 用于生成密码散列值的盐（salt）。这应该是一个随机生成的字符串，对于每个用户都是唯一的。
    private static final String SALT = "YourUniqueSaltString";

    // 生成密码的散列值
    public static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update((SALT + password).getBytes(StandardCharsets.UTF_8));
            byte[] digest = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // 验证密码是否正确
    public static boolean verifyPassword(String password, String storedHash) {
        return storedHash.equals(hashPassword(password));
    }

    public static void main(String[] args) {
        String password = "myPassword";
        String hashedPassword = hashPassword(password);
        System.out.println("Hashed Password: " + hashedPassword);

        boolean isCorrect = verifyPassword(password, hashedPassword);
        System.out.println("Password Correct: " + isCorrect);
    }
}