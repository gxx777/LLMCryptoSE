import java.security.SecureRandom;

public class RandomExample2 {
    private static final SecureRandom secureRandom = new SecureRandom();

    public static int generateRandomInt(int min, int max) {
        if (min >= max) {
            throw new IllegalArgumentException("最大值必须大于最小值");
        }

        // 计算范围
        int range = max - min + 1;

        // 生成随机数并调整到指定范围
        return secureRandom.nextInt(range) + min;
    }

    public static void main(String[] args) {
        int min = 1;
        int max = 100;

        int randomInt = generateRandomInt(min, max);
        System.out.println("生成的随机数为： " + randomInt);
    }
}