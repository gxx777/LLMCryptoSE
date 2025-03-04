import java.security.SecureRandom;

public class RandomExample1 {

    private static final SecureRandom secureRandom = new SecureRandom();

    public static void main(String[] args) {
        // 生成一个安全的随机整数
        int randomInt = secureRandom.nextInt();
        System.out.println("随机整数: " + randomInt);

        // 生成一个安全的随机长整数
        long randomLong = secureRandom.nextLong();
        System.out.println("随机长整数: " + randomLong);

        // 生成一个安全的随机浮点数（0.0到1.0之间）
        float randomFloat = secureRandom.nextFloat();
        System.out.println("随机浮点数: " + randomFloat);

        // 生成一个安全的随机双精度浮点数（0.0到1.0之间）
        double randomDouble = secureRandom.nextDouble();
        System.out.println("随机双精度浮点数: " + randomDouble);

        // 生成一个指定范围内的随机整数（例如：1到100之间）
        int randomBetweenOneAndHundred = secureRandom.nextInt(100) + 1;
        System.out.println("1到100之间的随机整数: " + randomBetweenOneAndHundred);
    }
}