import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashExample3 {

    public static String encryptString(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(input.getBytes());
            
            StringBuilder hexString = new StringBuilder();
            for (byte hashByte : encodedhash) {
                String hex = Integer.toHexString(0xff & hashByte);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            
            return hexString.toString();
            
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Hashing algorithm not found");
            return null;
        }
    }
    
    public static void main(String[] args) {
        String input = "hello world";
        String encryptedString = encryptString(input);
        System.out.println("Input string: " + input);
        System.out.println("Encrypted string: " + encryptedString);
    }
}