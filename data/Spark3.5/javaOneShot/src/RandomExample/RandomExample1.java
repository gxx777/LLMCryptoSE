import java.security.SecureRandom;

public class RandomExample1 {
    public static void main(String[] args) {
        // 创建一个安全随机数生成器
        SecureRandom secureRandom = new SecureRandom();

        // 生成一个0到100之间的随机整数
        int randomInt = secureRandom.nextInt(101);
        System.out.println("随机整数： " + randomInt);

        // 生成一个0到1之间的随机浮点数
        double randomDouble = secureRandom.nextDouble();
        System.out.println("随机浮点数： " + randomDouble);
    }
}