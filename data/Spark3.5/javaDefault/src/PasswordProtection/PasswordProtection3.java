import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class PasswordProtection3 {
    private static final int SALT_LENGTH = 16;
    private static final int ITERATIONS = 10000;
    private byte[] salt;
    private byte[] hashedPassword;

    public PasswordProtection3(String password) {
        this.salt = generateSalt();
        this.hashedPassword = hashPassword(password, this.salt);
    }

    private byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        new java.security.SecureRandom().nextBytes(salt);
        return salt;
    }

    private byte[] hashPassword(String password, byte[] salt) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        md.update(salt);
        byte[] hashedPassword = md.digest(password.getBytes());
        for (int i = 1; i < ITERATIONS; i++) {
            md.reset();
            hashedPassword = md.digest(hashedPassword);
        }
        return hashedPassword;
    }

    public boolean checkPassword(String password) {
        byte[] inputHashedPassword = hashPassword(password, this.salt);
        return Arrays.equals(this.hashedPassword, inputHashedPassword);
    }
}