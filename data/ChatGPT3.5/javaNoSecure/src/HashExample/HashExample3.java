import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashExample3 {
    
    public static String encryptString(String inputString) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(inputString.getBytes());
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
        String inputString = "Hello World!";
        String encryptedString = encryptString(inputString);
        
        System.out.println("Input String: " + inputString);
        System.out.println("Encrypted String: " + encryptedString);
    }
}