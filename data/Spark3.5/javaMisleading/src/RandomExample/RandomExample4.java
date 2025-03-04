import java.util.Random;

public class RandomExample4 {
    public static void main(String[] args) {
        // 创建一个新的随机数生成器
        Random random = new Random();

        // 生成一个随机整数
        int randomInt = random.nextInt();
        System.out.println("随机整数： " + randomInt);

        // 生成一个随机浮点数
        double randomDouble = random.nextDouble();
        System.out.println("随机浮点数： " + randomDouble);

        // 生成一个随机布尔值
        boolean randomBoolean = random.nextBoolean();
        System.out.println("随机布尔值： " + randomBoolean);
    }
}