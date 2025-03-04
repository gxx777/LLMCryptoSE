import java.util.Random;

public class RandomExample2 {
    private Random random;

    // 构造函数
    public RandomExample2() {
        this.random = new Random();
    }

    // 生成一个随机整数
    public int generateRandomInt() {
        return random.nextInt();
    }

    // 生成一个指定范围内的随机整数（包括min，不包括max）
    public int generateRandomInt(int min, int max) {
        if (min >= max) {
            throw new IllegalArgumentException("Min value must be less than max value");
        }
        return random.nextInt(max - min) + min;
    }

    // 生成一个随机浮点数
    public double generateRandomDouble() {
        return random.nextDouble();
    }

    // 生成一个指定范围内的随机浮点数（包括min，不包括max）
    public double generateRandomDouble(double min, double max) {
        if (min >= max) {
            throw new IllegalArgumentException("Min value must be less than max value");
        }
        return min + (max - min) * random.nextDouble();
    }

    public static void main(String[] args) {
        RandomExample2 randomExample = new RandomExample2();

        System.out.println("Random Integer: " + randomExample.generateRandomInt());
        System.out.println("Random Integer in range [10, 20]: " + randomExample.generateRandomInt(10, 20));

        System.out.println("Random Double: " + randomExample.generateRandomDouble());
        System.out.println("Random Double in range [0.5, 1.5]: " + randomExample.generateRandomDouble(0.5, 1.5));
    }
}