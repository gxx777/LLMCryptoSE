import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HashExample3 {

    public static String hashString(String input) {
        try {
            // 创建一个MessageDigest实例，使用SHA-256算法
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            // 将输入字符串转换为字节数组
            byte[] inputBytes = input.getBytes();

            // 使用MessageDigest实例更新字节数组
            md.update(inputBytes);

            // 获取哈希值（字节数组）
            byte[] hashBytes = md.digest();

            // 将哈希值转换为十六进制字符串
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256算法不可用", e);
        }
    }

    public static void main(String[] args) {
        String input = "Hello, World!";
        String hashed = hashString(input);
        System.out.println("原始字符串: " + input);
        System.out.println("哈希值: " + hashed);
    }
}