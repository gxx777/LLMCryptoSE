import java.security.SecureRandom;

public class RandomExample3 {

    private static final SecureRandom random = new SecureRandom();

    // 阻止外部通过new关键字创建实例
    private RandomExample3() {}

    // 生成随机整数
    public static int generateRandomInt(int min, int max) {
        if (min >= max) {
            throw new IllegalArgumentException("Min value must be less than max value");
        }
        return min + random.nextInt(max - min + 1);
    }

    // 生成随机浮点数
    public static double generateRandomDouble() {
        return random.nextDouble();
    }

    // 生成随机字节数组
    public static byte[] generateRandomBytes(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("Length must be greater than 0");
        }
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    // 示例：生成一个随机的安全令牌
    public static String generateSecureToken(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("Length must be greater than 0");
        }
        byte[] bytes = generateRandomBytes(length);
        return new String(bytes);
    }

    public static void main(String[] args) {
        // 测试生成随机整数
        System.out.println("Random Int: " + generateRandomInt(1, 100));

        // 测试生成随机浮点数
        System.out.println("Random Double: " + generateRandomDouble());

        // 测试生成随机字节数组
        System.out.println("Random Bytes: " + new String(generateRandomBytes(10)));

        // 测试生成安全令牌
        System.out.println("Secure Token: " + generateSecureToken(16));
    }
}