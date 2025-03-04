import java.util.Random;

public class RandomExample3 {
    private Random random;

    public RandomExample3() {
        this.random = new Random();
    }

    // 生成并返回一个0到100之间的随机整数
    public int generateRandomInt() {
        return random.nextInt(101);
    }

    // 生成并返回一个随机的浮点数，范围在0.0（包含）到1.0（不包含）之间
    public double generateRandomFloat() {
        return random.nextDouble();
    }

    // 生成并返回一个随机的布尔值
    public boolean generateRandomBoolean() {
        return random.nextBoolean();
    }

    public static void main(String[] args) {
        RandomExample3 example = new RandomExample3();

        System.out.println("随机整数: " + example.generateRandomInt());
        System.out.println("随机浮点数: " + example.generateRandomFloat());
        System.out.println("随机布尔值: " + example.generateRandomBoolean());
    }
}