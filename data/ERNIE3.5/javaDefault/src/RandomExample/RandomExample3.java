import java.security.SecureRandom;

public class RandomExample3 {
    private static final SecureRandom random = new SecureRandom();

    // 生成一个随机整数
    public static int generateRandomInt(int min, int max) {
        if (min >= max) {
            throw new IllegalArgumentException("Min value must be less than max value");
        }
        return min + random.nextInt(max - min + 1);
    }

    // 生成一个随机浮点数
    public static double generateRandomDouble(double min, double max) {
        return min + random.nextDouble() * (max - min);
    }

    // 生成一个随机布尔值
    public static boolean generateRandomBoolean() {
        return random.nextBoolean();
    }

    // 生成一个随机字节数组
    public static byte[] generateRandomByteArray(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    // 主函数，用于测试
    public static void main(String[] args) {
        System.out.println("Random Integer: " + generateRandomInt(1, 100));
        System.out.println("Random Double: " + generateRandomDouble(0.0, 1.0));
        System.out.println("Random Boolean: " + generateRandomBoolean());
        System.out.println("Random Byte Array: " + new String(generateRandomByteArray(10)));
    }
}