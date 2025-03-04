import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashExample4 {

    private static final String HASH_ALGORITHM = "SHA-256";

    public static String hashString(String input) {
        try {
            // 创建一个MessageDigest实例
            MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);

            // 使用输入字符串的字节更新哈希值
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

    public static void main(String[] args) {
        String originalString = "Hello, World!";
        String hashedString = hashString(originalString);
        System.out.println("Original String: " + originalString);
        System.out.println("Hashed String: " + hashedString);
    }
}