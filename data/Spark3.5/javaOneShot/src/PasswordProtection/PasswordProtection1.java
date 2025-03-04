import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class PasswordProtection1 {
    private static final int SALT_LENGTH = 16;
    private byte[] salt;
    private byte[] hashedPassword;

    public PasswordProtection1(String password) throws NoSuchAlgorithmException {
        this.salt = generateSalt();
        this.hashedPassword = hashPassword(password, this.salt);
    }

    private byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[SALT_LENGTH];
        random.nextBytes(bytes);
        return bytes;
    }

    private byte[] hashPassword(String password, byte[] salt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt);
        return md.digest(password.getBytes());
    }

    public boolean checkPassword(String password) throws NoSuchAlgorithmException {
        byte[] testHash = hashPassword(password, this.salt);
        return Arrays.equals(this.hashedPassword, testHash);
    }
}