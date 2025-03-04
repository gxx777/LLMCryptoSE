import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class HashExample3 {
    public static void main(String[] args) {
        String input = "Hello, world!";
        String hashed = hashWithSalt(input);
        System.out.println("Hashed string: " + hashed);
    }

    public static String hashWithSalt(String input) {
        try {
            // Generate a random salt
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);

            // Combine the input string and salt
            String combinedInput = input + Base64.getEncoder().encodeToString(salt);

            // Create a MessageDigest instance for MD5
            MessageDigest md = MessageDigest.getInstance("MD5");

            // Update the digest with the combined input
            md.update(combinedInput.getBytes());

            // Get the hashed bytes
            byte[] hashedBytes = md.digest();

            // Encode the hashed bytes as a Base64 string
            return Base64.getEncoder().encodeToString(hashedBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error: Unable to find MD5 algorithm", e);
        }
    }
}