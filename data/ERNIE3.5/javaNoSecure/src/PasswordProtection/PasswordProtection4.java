import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class PasswordProtection4 {

    private String salt;
    private byte[] hashedPassword;

    public PasswordProtection4(String password) {
        this.salt = generateSalt();
        this.hashedPassword = hashPassword(password, salt);
    }

    public boolean verifyPassword(String password) {
        byte[] hashedInput = hashPassword(password, salt);
        return Arrays.equals(hashedPassword, hashedInput);
    }

    private String generateSalt() {
        // 生成随机的盐值，这里简单地使用UUID，但在真实场景中应该使用更安全的随机生成器
        return java.util.UUID.randomUUID().toString();
    }

    private byte[] hashPassword(String password, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update((salt + password).getBytes());
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}