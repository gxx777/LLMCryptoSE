import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashExample3 {

    public static String encryptString(String input) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] hash = messageDigest.digest(input.getBytes());

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
        String originalString = "Hello, World!";
        String encryptedString = encryptString(originalString);

        System.out.println("Original String: " + originalString);
        System.out.println("Encrypted String: " + encryptedString);
    }
}