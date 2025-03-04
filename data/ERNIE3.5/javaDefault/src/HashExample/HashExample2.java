import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashExample2 {

    private static final String HASH_ALGORITHM = "SHA-256";

    /**
     * 使用SHA-256算法对给定的字符串进行哈希加密
     *
     * @param input 要加密的字符串
     * @return 加密后的哈希值（32位十六进制字符串）
     */
    public static String hash(String input) {
        try {
            // 获取MessageDigest实例
            MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);

            // 更新要哈希的数据
            md.update(input.getBytes(StandardCharsets.UTF_8));

            // 计算哈希值
            byte[] hashBytes = md.digest();

            // 将字节转换为十六进制字符串
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Could not find hash algorithm", e);
        }
    }

    public static void main(String[] args) {
        // 测试哈希函数
        String input = "Hello, World!";
        String hashed = hash(input);
        System.out.println("Original String: " + input);
        System.out.println("Hashed String: " + hashed);
    }
}