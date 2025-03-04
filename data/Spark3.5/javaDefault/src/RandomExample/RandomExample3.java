import java.security.SecureRandom;

public class RandomExample3 {
    private static final SecureRandom secureRandom = new SecureRandom();

    public static int generateRandomNumber(int min, int max) {
        if (min >= max) {
            throw new IllegalArgumentException("最大值必须大于最小值");
        }

        return secureRandom.nextInt((max - min) + 1) + min;
    }

    public static void main(String[] args) {
        int min = 1;
        int max = 100;
        int randomNumber = generateRandomNumber(min, max);
        System.out.println("生成的随机数为： " + randomNumber);
    }
}