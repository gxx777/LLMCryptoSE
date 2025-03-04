import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class PasswordProtection2 {
    private Map<String, String> passwordMap = new HashMap<>();

    public void storePassword(String username, String password) throws NoSuchAlgorithmException {
        String hashedPassword = hashPassword(password);
        passwordMap.put(username, hashedPassword);
    }

    public boolean verifyPassword(String username, String password) throws NoSuchAlgorithmException {
        String storedHashedPassword = passwordMap.get(username);
        if (storedHashedPassword == null) {
            return false;
        }
        String hashedPassword = hashPassword(password);
        return storedHashedPassword.equals(hashedPassword);
    }

    private String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(password.getBytes());
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static void main(String[] args) {
        PasswordProtection2 passwordProtection = new PasswordProtection2();

        try {
            // Storing a password
            passwordProtection.storePassword("user1", "password123");

            // Verifying a password
            boolean isPasswordCorrect = passwordProtection.verifyPassword("user1", "password123");
            System.out.println("Is password correct? " + isPasswordCorrect);

            // Verifying an incorrect password
            boolean isPasswordIncorrect = passwordProtection.verifyPassword("user1", "wrongpassword");
            System.out.println("Is password incorrect? " + isPasswordIncorrect);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}