import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashExample2 {
  
    public String encryptString(String input) {
        String output = null;
        
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(input.getBytes());
            byte[] bytes = md.digest();
            
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            
            output = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error encrypting string: " + e.getMessage());
        }
        
        return output;
    }
  
    public static void main(String[] args) {
        HashExample2 hashExample = new HashExample2();
        String input = "Hello World!";
        String encryptedString = hashExample.encryptString(input);
        
        System.out.println("Input String: " + input);
        System.out.println("Encrypted String: " + encryptedString);
    }
}