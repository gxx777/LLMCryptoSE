import java.util.Random;

public class RandomExample2 {
    private static final Random random = new Random();

    // 线程安全的方法，生成并返回一个随机整数
    public static int generateRandomInt() {
        return random.nextInt();
    }

    // 线程安全的方法，生成并返回一个指定范围内的随机整数
    public static int generateRandomInt(int start, int end) {
        if (start >= end) {
            throw new IllegalArgumentException("Start value must be less than end value");
        }
        return start + random.nextInt(end - start);
    }

    // 线程安全的方法，生成并返回一个随机浮点数
    public static double generateRandomDouble() {
        return random.nextDouble();
    }

    // 线程安全的方法，生成并返回一个指定范围内的随机浮点数
    public static double generateRandomDouble(double start, double end) {
        if (start >= end) {
            throw new IllegalArgumentException("Start value must be less than end value");
        }
        return start + (end - start) * random.nextDouble();
    }

    // 禁止实例化
    private RandomExample2() {}
}