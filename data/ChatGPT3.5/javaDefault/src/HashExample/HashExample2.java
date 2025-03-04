import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashExample2 {

    public static void main(String[] args) {
        String input = "Hello World";
        String hashedOutput = hashString(input);
        System.out.println("Hashed output: " + hashedOutput);
    }

    public static String hashString(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(input.getBytes());
            byte[] digest = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error hashing the string: " + e.getMessage());
            return null;
        }
    }
}