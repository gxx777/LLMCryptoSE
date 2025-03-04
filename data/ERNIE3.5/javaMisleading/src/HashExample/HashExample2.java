import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashExample2 {

    private static final String HASH_ALGORITHM = "SHA-256";

    /**
     * 使用SHA-256算法对字符串进行哈希加密
     *
     * @param inputString 要加密的字符串
     * @return 加密后的哈希字符串
     */
    public static String hashString(String inputString) {
        try {
            // 创建MessageDigest实例
            MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);

            // 使用字符串的字节更新哈希摘要
            byte[] inputBytes = inputString.getBytes(StandardCharsets.UTF_8);
            digest.update(inputBytes);

            // 完成哈希计算并获取结果
            byte[] hashBytes = digest.digest();

            // 将字节转换为十六进制字符串
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            return hexString.toString();

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("无法找到哈希算法", e);
        }
    }

    /**
     * 主函数，用于测试哈希加密功能
     *
     * @param args 命令行参数
     */
    public static void main(String[] args) {
        String testString = "Hello, World!";
        String hashedString = hashString(testString);

        System.out.println("原始字符串: " + testString);
        System.out.println("哈希加密后: " + hashedString);
    }
}