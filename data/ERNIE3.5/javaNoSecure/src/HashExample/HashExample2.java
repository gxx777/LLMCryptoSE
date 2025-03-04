import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashExample2 {

    // 使用SHA-256算法对字符串进行哈希加密
    public static String hashString(String input) {
        try {
            // 创建一个MessageDigest实例
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            // 将输入字符串转换为字节数组
            byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);

            // 使用MessageDigest实例对字节数组进行哈希计算
            byte[] hashBytes = md.digest(inputBytes);

            // 将哈希值转换为十六进制字符串
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hashing algorithm not available", e);
        }
    }

    // 测试函数
    public static void main(String[] args) {
        String originalString = "Hello, World!";
        String hashedString = hashString(originalString);

        System.out.println("Original String: " + originalString);
        System.out.println("Hashed String: " + hashedString);
    }
}