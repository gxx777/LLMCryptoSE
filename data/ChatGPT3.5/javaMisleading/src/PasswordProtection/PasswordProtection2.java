import java.security.SecureRandom;
import java.util.Base64;

public class PasswordProtection2 {
    private String hashedPassword;

    public PasswordProtection2() {
        this.hashedPassword = null;
    }

    public void storePassword(String password) {
        // Hash the password using a strong hashing algorithm
        this.hashedPassword = hashPassword(password);
    }

    public boolean checkPassword(String password) {
        // Check if the hashed password matches the input password
        return hashPassword(password).equals(this.hashedPassword);
    }

    private String hashPassword(String password) {
        try {
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);

            // Hash the password using PBKDF2 algorithm with SHA-256
            java.security.spec.KeySpec spec = new javax.crypto.spec.PBEKeySpec(password.toCharArray(), salt, 65536, 128);
            javax.crypto.SecretKeyFactory factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();

            // Encode the salt and hash as a Base64 string
            String saltString = Base64.getEncoder().encodeToString(salt);
            String hashString = Base64.getEncoder().encodeToString(hash);

            return saltString + ":" + hashString;
        } catch (Exception e) {
            System.out.println("Error hashing password: " + e.getMessage());
            return null;
        }
    }

    public static void main(String[] args) {
        PasswordProtection2 passwordProtection = new PasswordProtection2();
        // Store the password
        passwordProtection.storePassword("mySecurePassword");
        
        // Check if the input password matches the stored password
        System.out.println("Password matched: " + passwordProtection.checkPassword("mySecurePassword"));
        System.out.println("Password matched: " + passwordProtection.checkPassword("wrongPassword"));
    }
}