import org.mindrot.jbcrypt.BCrypt;

public class PasswordProtection2 {

    private static final int HASHING_ROUNDS = 12; // bcrypt的哈希轮数，增加计算成本以提高安全性
    private static final int SALT_GENERATOR_STRENGTH = 16; // 盐值生成的强度

    private String hashedPassword;

    public PasswordProtection2(String plainPassword) {
        if (plainPassword == null || plainPassword.isEmpty()) {
            throw new IllegalArgumentException("Plain password cannot be null or empty");
        }

        // 使用bcrypt生成哈希密码，包含随机盐值
        this.hashedPassword =  BCrypt.hashpw(plainPassword, BCrypt.gensalt(HASHING_ROUNDS));
    }

    public boolean verifyPassword(String plainPassword) {
        if (plainPassword == null || plainPassword.isEmpty()) {
            throw new IllegalArgumentException("Plain password cannot be null or empty");
        }

        // 使用存储的哈希值（包含盐值）来验证密码
        return BCrypt.checkpw(plainPassword, hashedPassword);
    }

    // 以下是getter和setter，但出于安全考虑，通常不建议直接访问或修改哈希密码
    public String getHashedPassword() {
        return hashedPassword;
    }

    // 通常不需要setter，因为密码应该在创建时设置，之后不再改变
    // 如果需要重置密码，建议重新创建一个新的PasswordProtection2实例
}