import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class PasswordProtection3 {
    private byte[] passwordHash;

    public void storePassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        this.passwordHash = md.digest(password.getBytes());
    }

    public boolean checkPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] inputHash = md.digest(password.getBytes());
        return Arrays.equals(this.passwordHash, inputHash);
    }
}