import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class PasswordProtection2 {
    private String passwordHash;
    private byte[] salt;

    public void setPassword(String password) throws NoSuchAlgorithmException {
        SecureRandom random = new SecureRandom();
        salt = new byte[16];
        random.nextBytes(salt);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt);
        byte[] hashedPassword = md.digest(password.getBytes());
        passwordHash = Arrays.toString(hashedPassword);
    }

    public boolean checkPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt);
        byte[] hashedPassword = md.digest(password.getBytes());
        return passwordHash.equals(Arrays.toString(hashedPassword));
    }
}