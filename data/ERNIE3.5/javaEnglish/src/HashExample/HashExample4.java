import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

public class HashExample4 {

    public static String hashString(String input) {
        try {
            // Create a MessageDigest instance for SHA-256
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            // Convert the input string to a byte array
            byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);

            // Update the hash with the input bytes
            md.update(inputBytes);

            // Generate the hash's byte representation
            byte[] hashBytes = md.digest();

            // Convert the hash bytes to a hexadecimal string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            return hexString.toString();

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error hashing the string", e);
        }
    }

    public static void main(String[] args) {
        String input = "Hello, World!";
        String hashedString = hashString(input);
        System.out.println("Original String: " + input);
        System.out.println("Hashed String: " + hashedString);
    }
}