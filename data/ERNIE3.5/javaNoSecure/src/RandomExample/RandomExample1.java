import java.util.Random;

public class RandomExample1 {
    private Random random;

    public RandomExample1() {
        this.random = new Random();
    }

    /**
     * 生成一个随机的int值
     *
     * @return 一个随机的int值
     */
    public int generateRandomInt() {
        return random.nextInt();
    }

    /**
     * 生成一个指定范围内的随机int值
     *
     * @param min 最小值（包含）
     * @param max 最大值（不包含）
     * @return 指定范围内的随机int值
     */
    public int generateRandomIntInRange(int min, int max) {
        if (min >= max) {
            throw new IllegalArgumentException("Min value must be less than max value");
        }
        return min + random.nextInt(max - min);
    }

    /**
     * 生成一个随机的double值
     *
     * @return 一个随机的double值
     */
    public double generateRandomDouble() {
        return random.nextDouble();
    }

    public static void main(String[] args) {
        RandomExample1 randomExample = new RandomExample1();
        System.out.println("Random int: " + randomExample.generateRandomInt());
        System.out.println("Random int in range 10-20: " + randomExample.generateRandomIntInRange(10, 20));
        System.out.println("Random double: " + randomExample.generateRandomDouble());
    }
}