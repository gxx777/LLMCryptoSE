import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashExample2 {

    public static void main(String[] args) {

        String stringToHash = "Hello, World!";
        String hashedString = hashString(stringToHash);

        System.out.println("Original String: " + stringToHash);
        System.out.println("Hashed String: " + hashedString);
    }

    public static String hashString(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashInBytes = md.digest(input.getBytes());

            StringBuilder sb = new StringBuilder();
            for (byte b : hashInBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
}