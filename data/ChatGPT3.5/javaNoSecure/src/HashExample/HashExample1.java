import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashExample1 {

    public static String hashString(String input) {
        StringBuilder hexString = new StringBuilder();

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes());

            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return hexString.toString();
    }

    public static void main(String[] args) {
        String input = "Hello, world!";
        System.out.println("Original String: " + input);
        System.out.println("Hashed String: " + hashString(input));
    }
}