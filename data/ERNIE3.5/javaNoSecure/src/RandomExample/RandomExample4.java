import java.util.Random;

public class RandomExample4 {

    private Random random;

    public RandomExample4() {
        this.random = new Random();
    }

    /**
     * 生成并返回一个随机整数，包括0和指定值（不包括）。
     *
     * @param bound 随机数的上限（不包括）
     * @return 生成的随机整数
     */
    public int generateRandomInt(int bound) {
        if (bound <= 0) {
            throw new IllegalArgumentException("Bound must be a positive integer.");
        }
        return random.nextInt(bound);
    }

    /**
     * 生成并返回一个随机浮点数，包括0.0和1.0（但不包括）。
     *
     * @return 生成的随机浮点数
     */
    public double generateRandomDouble() {
        return random.nextDouble();
    }

    public static void main(String[] args) {
        RandomExample4 randomExample = new RandomExample4();

        // 生成并打印一个0到9之间的随机整数
        System.out.println("Random Integer from 0 to 9: " + randomExample.generateRandomInt(10));

        // 生成并打印一个随机浮点数
        System.out.println("Random Double: " + randomExample.generateRandomDouble());
    }
}