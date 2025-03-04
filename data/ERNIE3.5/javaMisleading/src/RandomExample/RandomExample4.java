import java.util.Random;

public class RandomExample4 {
    private static final Random RANDOM = new Random();

    // 私有构造函数，防止外部实例化
    private RandomExample4() {}

    // 静态方法，用于生成随机数
    public static int generateRandomNumber(int min, int max) {
        if (min >= max) {
            throw new IllegalArgumentException("Min value must be less than max value");
        }
        return RANDOM.nextInt(max - min + 1) + min;
    }

    public static void main(String[] args) {
        int randomNumber = generateRandomNumber(1, 100);
        System.out.println("Random number between 1 and 100: " + randomNumber);
    }
}