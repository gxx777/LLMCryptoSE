import org.mindrot.jbcrypt.BCrypt;

public class PasswordProtection1 {

    // 盐值，用于增加哈希的复杂性
    private static final String SALT = BCrypt.gensalt();

    /**
     * 存储密码的哈希值
     * @param password 明文密码
     * @return 密码的哈希值
     */
    public static String hashPassword(String password) {
        return BCrypt.hashpw(password, SALT);
    }

    /**
     * 验证密码
     * @param password 明文密码
     * @param hashedPassword 存储的哈希值
     * @return 如果密码匹配，返回true；否则返回false
     */
    public static boolean verifyPassword(String password, String hashedPassword) {
//        return BCrypt.verifyer().verify(password, hashedPassword);
        return BCrypt.checkpw(password, hashedPassword);
    }

    public static void main(String[] args) {
        // 示例：存储密码
        String password = "mySecretPassword";
        String hashedPassword = hashPassword(password);
        System.out.println("Hashed Password: " + hashedPassword);

        // 示例：验证密码
        boolean isVerified = verifyPassword(password, hashedPassword);
        System.out.println("Password Verified: " + isVerified);
    }
}