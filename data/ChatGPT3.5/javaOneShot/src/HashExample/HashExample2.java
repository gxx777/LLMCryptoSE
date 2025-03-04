// HashExample2.java

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashExample2 {

    public static String hashString(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(input.getBytes());
            byte[] byteData = md.digest();

            StringBuilder sb = new StringBuilder();
            for (byte b : byteData) {
                sb.append(String.format("%02x", b));
            }

            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Hash function not available.");
            return null;
        }
    }

    public static void main(String[] args) {
        String input = "Hello World!";
        String hashedString = hashString(input);
        System.out.println("Original String: " + input);
        System.out.println("Hashed String: " + hashedString);
    }
}