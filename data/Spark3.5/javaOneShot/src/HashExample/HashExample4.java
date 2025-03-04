import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class HashExample4 {

    public static void main(String[] args) {
        String input = "这是一个需要加密的字符串";
        String hashedString = hashString(input);
        System.out.println("原始字符串： " + input);
        System.out.println("哈希后的字符串： " + hashedString);
    }

    public static String hashString(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("无法找到SHA-256算法", e);
        }
    }
}