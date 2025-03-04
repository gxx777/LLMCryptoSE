import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashExample4 {

    public static String encryptString(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes());
            StringBuilder hexString = new StringBuilder();

            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        String input = "HelloWorld";
        String encryptedString = encryptString(input);
        System.out.println("Encrypted String: " + encryptedString);
    }
}