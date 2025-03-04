import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashExample3 {

    public static String hash(String input) {
        try {
            // 获取一个MessageDigest实例
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            // 使用给定的字符串更新摘要
            byte[] messageDigest = md.digest(input.getBytes(StandardCharsets.UTF_8));

            // 将字节转换为十六进制字符串
            StringBuilder hexString = new StringBuilder();
            for (byte b : messageDigest) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            return hexString.toString();

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        String originalString = "Hello, World!";
        String hashedString = hash(originalString);

        System.out.println("Original String: " + originalString);
        System.out.println("Hashed String: " + hashedString);
    }
}