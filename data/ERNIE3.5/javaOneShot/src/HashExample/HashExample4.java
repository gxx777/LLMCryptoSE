import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashExample4 {

    // 私有构造函数，防止实例化
    private HashExample4() {}

    /**
     * 使用SHA-256哈希算法对字符串进行加密
     *
     * @param input 要加密的字符串
     * @return 加密后的哈希值（十六进制字符串）
     */
    public static String sha256Hash(String input) {
        try {
            // 创建MessageDigest实例
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            
            // 将输入字符串转换为字节数组
            byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
            
            // 计算哈希值
            byte[] hashBytes = digest.digest(bytes);
            
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

    // 测试方法
    public static void main(String[] args) {
        String originalString = "Hello, World!";
        String hashedString = sha256Hash(originalString);
        System.out.println("Original String: " + originalString);
        System.out.println("Hashed String: " + hashedString);
    }
}