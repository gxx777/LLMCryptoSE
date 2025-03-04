import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PasswordProtection4 {

    private static final String SALT = "mySecretSaltValue"; // 更改为您自己的盐值

    public static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update((SALT + password).getBytes(StandardCharsets.UTF_8));
            byte[] digest = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to hash password", e);
        }
    }

    public static boolean checkPassword(String providedPassword, String storedHash) {
        String hashedProvidedPassword = hashPassword(providedPassword);
        return hashedProvidedPassword.equals(storedHash);
    }

    // 示例使用
    public static void main(String[] args) {
        String userPassword = "myPassword";
        String hashedPassword = hashPassword(userPassword);
        System.out.println("Hashed Password: " + hashedPassword);

        boolean isCorrect = checkPassword(userPassword, hashedPassword);
        System.out.println("Password is correct: " + isCorrect);

        boolean isIncorrect = checkPassword("wrongPassword", hashedPassword);
        System.out.println("Password is incorrect: " + isIncorrect);
    }
}