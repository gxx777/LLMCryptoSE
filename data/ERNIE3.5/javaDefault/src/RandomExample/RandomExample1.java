import java.util.Random;

public class RandomExample1 {

    private static final Random RANDOM = new Random();

    public static void main(String[] args) {
        // 生成一个0到99之间的随机整数
        int randomInt = RANDOM.nextInt(100);
        System.out.println("随机整数: " + randomInt);

        // 生成一个随机的浮点数
        double randomDouble = RANDOM.nextDouble();
        System.out.println("随机浮点数: " + randomDouble);

        // 生成一个随机的布尔值
        boolean randomBoolean = RANDOM.nextBoolean();
        System.out.println("随机布尔值: " + randomBoolean);
    }
}