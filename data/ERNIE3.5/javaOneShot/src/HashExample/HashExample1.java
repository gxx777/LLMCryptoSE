import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashExample1 {

    /**
     * 使用SHA-256算法加密字符串
     *
     * @param inputString 要加密的字符串
     * @return 加密后的字符串（十六进制表示）
     */
    public static String sha256Hash(String inputString) {
        try {
            // 获取SHA-256的MessageDigest实例
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // 将输入字符串转换为字节数组
            byte[] inputBytes = inputString.getBytes(StandardCharsets.UTF_8);

            // 使用MessageDigest的update方法更新摘要
            digest.update(inputBytes);

            // 使用digest方法完成哈希计算，并获取结果
            byte[] hashBytes = digest.digest();

            // 将字节数组转换为十六进制字符串
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            return hexString.toString();

        } catch (NoSuchAlgorithmException e) {
            // 如果SHA-256算法不可用，抛出异常
            throw new RuntimeException("SHA-256 algorithm is not available", e);
        }
    }

    public static void main(String[] args) {
        // 测试字符串
        String testString = "Hello, World!";

        // 对字符串进行哈希
        String hashedString = sha256Hash(testString);

        // 输出结果
        System.out.println("Original String: " + testString);
        System.out.println("Hashed String: " + hashedString);
    }
}