import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashExample3 {
    
    public static String encryptString(String input) {
        try {
            // Create MessageDigest instance for MD5
            MessageDigest md = MessageDigest.getInstance("MD5");
            // Add input string bytes to digest
            md.update(input.getBytes());
            // Get the hash's bytes 
            byte[] hashBytes = md.digest();
            
            // This byte[] has bytes in decimal format, convert it to hexadecimal format
            StringBuilder sb = new StringBuilder();
            for (byte hashByte : hashBytes) {
                sb.append(Integer.toString((hashByte & 0xff) + 0x100, 16).substring(1));
            }
            
            // Return the encrypted hash
            return sb.toString();
            
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error while creating hash: " + e.getMessage());
            return null;
        }
    }

    public static void main(String[] args) {
        String input = "Hello, world!";
        String encryptedString = encryptString(input);
        System.out.println("Encrypted string: " + encryptedString);
    }
}