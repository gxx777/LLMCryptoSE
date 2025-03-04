import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashExample3 {

    private static final String HASH_ALGORITHM = "SHA-256";

    // 使用SHA-256哈希算法对字符串进行哈希
    public static String hashString(String input) {
        try {
            // 获取SHA-256哈希算法的MessageDigest实例
            MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);

            // 使用给定的字符串更新哈希值
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));

            // 将字节转换为十六进制字符串
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            return hexString.toString();

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hash algorithm not found", e);
        }
    }

    // 主方法，用于测试
    public static void main(String[] args) {
        String originalString = "Hello, world!";
        String hashedString = hashString(originalString);

        System.out.println("Original String: " + originalString);
        System.out.println("Hashed String: " + hashedString);
    }
}