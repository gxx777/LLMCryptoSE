import java.util.Random;

public class RandomExample3 {
    public static void main(String[] args) {
        // 创建一个Random对象
        Random random = new Random();

        // 生成一个随机整数
        int randomInt = random.nextInt();
        System.out.println("随机整数： " + randomInt);

        // 生成一个随机浮点数
        double randomDouble = random.nextDouble();
        System.out.println("随机浮点数： " + randomDouble);

        // 生成一个指定范围内的随机整数
        int randomIntInRange = random.nextInt(100); // 生成0到99之间的随机整数
        System.out.println("指定范围内的随机整数： " + randomIntInRange);

        // 生成一个指定范围内的随机浮点数
        double randomDoubleInRange = random.nextDouble() * 100; // 生成0到99之间的随机浮点数
        System.out.println("指定范围内的随机浮点数： " + randomDoubleInRange);
    }
}