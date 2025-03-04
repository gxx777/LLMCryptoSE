import java.util.Random;

public class RandomExample4 {
    public static void main(String[] args) {
        // 创建一个随机数生成器对象
        Random random = new Random();

        // 生成一个随机整数
        int randomNumber = random.nextInt();
        System.out.println("随机整数： " + randomNumber);

        // 生成一个0到100之间的随机整数
        int randomNumberInRange = random.nextInt(101);
        System.out.println("0到100之间的随机整数： " + randomNumberInRange);

        // 生成一个随机浮点数
        float randomFloat = random.nextFloat();
        System.out.println("随机浮点数： " + randomFloat);

        // 生成一个随机布尔值
        boolean randomBoolean = random.nextBoolean();
        System.out.println("随机布尔值： " + randomBoolean);
    }
}