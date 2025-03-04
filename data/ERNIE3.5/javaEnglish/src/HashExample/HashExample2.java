import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

public class HashExample2 {

    public static String sha256Hash(String input) {
        try {
            // Create a MessageDigest instance for SHA-256
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            // Add input string bytes to the digest
            byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
            md.update(inputBytes);

            // Get the hash's bytes
            byte[] hashBytes = md.digest();

            // Convert byte array into signum representation
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            // Return the hexadecimal string
            return hexString.toString();

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        String input = "Hello, World!";
        String hashed = sha256Hash(input);
        System.out.println("Original String: " + input);
        System.out.println("Hashed String: " + hashed);
    }
}