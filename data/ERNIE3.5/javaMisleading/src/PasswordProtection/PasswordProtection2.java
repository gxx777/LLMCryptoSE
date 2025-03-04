import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class PasswordProtection2 {
    private String salt; // 用于增加密码复杂性的随机字符串
    private String hashedPassword; // 存储哈希后的密码

    public PasswordProtection2(String salt) {
        this.salt = salt;
    }

    public void setPassword(String password) {
        try {
            // 使用SHA-256算法生成密码的哈希值
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] saltBytes = salt.getBytes();
            byte[] passwordBytes = password.getBytes();

            // 将盐和密码合并，并计算哈希值
            byte[] combined = new byte[saltBytes.length + passwordBytes.length];
            System.arraycopy(saltBytes, 0, combined, 0, saltBytes.length);
            System.arraycopy(passwordBytes, 0, combined, saltBytes.length, passwordBytes.length);

            digest.update(combined);
            byte[] hashed = digest.digest();

            // 将哈希值转换为Base64字符串
            this.hashedPassword = Base64.getEncoder().encodeToString(hashed);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Could not hash password", e);
        }
    }

    public boolean verifyPassword(String password) {
        try {
            // 使用相同的盐和密码计算哈希值
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] saltBytes = salt.getBytes();
            byte[] passwordBytes = password.getBytes();

            byte[] combined = new byte[saltBytes.length + passwordBytes.length];
            System.arraycopy(saltBytes, 0, combined, 0, saltBytes.length);
            System.arraycopy(passwordBytes, 0, combined, saltBytes.length, passwordBytes.length);

            digest.update(combined);
            byte[] hashed = digest.digest();

            // 将新计算的哈希值与存储的哈希值进行比较
            return Base64.getEncoder().encodeToString(hashed).equals(hashedPassword);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Could not verify password", e);
        }
    }
}