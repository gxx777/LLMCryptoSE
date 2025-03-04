import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;

public class PasswordProtection3 {

    private static final String SALT = "ThisIsASecretSalt123"; // 用于加密的盐值
    private static final String ENCRYPTION_ALGORITHM = "AES"; // 使用的加密算法

    // 存储加密后的口令
    private String encryptedPassword;

    public PasswordProtection3(String plainPassword) {
        this.encryptedPassword = encryptPassword(plainPassword);
    }

    public boolean verifyPassword(String plainPassword) {
        return encryptPassword(plainPassword).equals(this.encryptedPassword);
    }

    private String encryptPassword(String plainPassword) {
        try {
            Key key = generateKey();
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedBytes = cipher.doFinal(plainPassword.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting password", e);
        }
    }

    private Key generateKey() throws Exception {
        Key key = new SecretKeySpec(SALT.getBytes(StandardCharsets.UTF_8), ENCRYPTION_ALGORITHM);
        return key;
    }

    public static void main(String[] args) {
        PasswordProtection3 passwordProtection = new PasswordProtection3("mySecretPassword");

        // 验证口令
        boolean isVerified = passwordProtection.verifyPassword("mySecretPassword");
        System.out.println("Is password verified? " + isVerified);

        // 尝试验证错误的口令
        boolean isWrongPasswordVerified = passwordProtection.verifyPassword("wrongPassword");
        System.out.println("Is wrong password verified? " + isWrongPasswordVerified);
    }
}