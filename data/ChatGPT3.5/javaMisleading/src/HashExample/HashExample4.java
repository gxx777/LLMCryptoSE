import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashExample4 {

    public static void main(String[] args) {
        String input = "Hello World!";
        String hashed = hashString(input);
        
        System.out.println("Original String: " + input);
        System.out.println("Hashed String: " + hashed);
    }
    
    public static String hashString(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = md.digest(input.getBytes());
            StringBuffer sb = new StringBuffer();
            
            for (int i = 0; i < hashedBytes.length; i++) {
                sb.append(Integer.toString((hashedBytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

}