import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class PasswordProtection3 {

    private static final int SALT_LENGTH = 16; // 盐的长度
    private static final int ITERATIONS = 100000; // 散列迭代的次数，增加计算成本以提高安全性

    // 存储盐和散列密码
    private byte[] salt;
    private String hashedPassword;

    // 生成新的盐和散列密码
    public void createHash(String password) throws NoSuchAlgorithmException {
        // 生成随机盐
        this.salt = new byte[SALT_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(this.salt);

        // 使用PBKDF2算法和盐来散列密码
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(
            (password + new String(salt, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8)
        );

        // 对散列值进行多次迭代以增加计算成本
        for (int i = 0; i < ITERATIONS; i++) {
            hash = digest.digest(hash);
        }

        // 将盐和散列值组合在一起并编码为Base64字符串
        this.hashedPassword = Base64.getEncoder().encodeToString(
            concat(salt, hash)
        );
    }

    // 验证提供的密码是否与存储的散列值匹配
    public boolean verifyPassword(String password) throws NoSuchAlgorithmException {
        // 从存储的散列值中提取盐和原始的散列值
        byte[] storedHashBytes = Base64.getDecoder().decode(hashedPassword);
        byte[] storedSalt = new byte[SALT_LENGTH];
        byte[] storedHash = new byte[storedHashBytes.length - SALT_LENGTH];

        System.arraycopy(storedHashBytes, 0, storedSalt, 0, SALT_LENGTH);
        System.arraycopy(storedHashBytes, SALT_LENGTH, storedHash, 0, storedHashBytes.length - SALT_LENGTH);

        // 使用相同的盐和PBKDF2算法来散列提供的密码
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] testHash = digest.digest(
            (password + new String(storedSalt, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8)
        );

        // 对散列值进行多次迭代
        for (int i = 0; i < ITERATIONS; i++) {
            testHash = digest.digest(testHash);
        }

        // 比较散列值是否匹配
        return java.util.Arrays.equals(testHash, storedHash);
    }

    // 辅助方法：将两个字节数组连接在一起
    private byte[] concat(byte[] first, byte[] second) {
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    // 测试方法（示例用途）
    public static void main(String[] args) {
        PasswordProtection3 passwordProtection = new PasswordProtection3();

        try {
            // 创建密码散列
            passwordProtection.createHash("mySecretPassword");
            System.out.println("Hashed Password: " + passwordProtection.hashedPassword);

            // 验证密码
            boolean isVerified = passwordProtection.verifyPassword("mySecretPassword");
            System.out.println("Password Verified: " + isVerified);

            // 错误的密码验证
            isVerified = passwordProtection.verifyPassword("wrongPassword");
            System.out.println("Password Verified (wrong password): " + isVerified);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}