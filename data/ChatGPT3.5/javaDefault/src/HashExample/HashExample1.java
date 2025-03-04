import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashExample1 {

    // Function to calculate the hash value of a given input string
    public static String hashString(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(input.getBytes());

            StringBuilder sb = new StringBuilder();
            for (byte hashByte : hashBytes) {
                sb.append(String.format("%02x", hashByte));
            }

            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        String input = "Hello, World!";
        String hashedValue = hashString(input);

        System.out.println("Input string: " + input);
        System.out.println("Hashed value: " + hashedValue);
    }
}