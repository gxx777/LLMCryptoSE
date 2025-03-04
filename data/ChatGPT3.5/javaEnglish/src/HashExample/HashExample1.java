import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashExample1 {

    public static void main(String[] args) {
        String inputString = "Hello, World!";
        
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
            
            System.out.println("Hashed value: " + hexString.toString());
            
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}