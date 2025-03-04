import java.util.Random;
import java.security.SecureRandom;

public class RandomExample2 {
    private static final Random random = new Random();
    private static final SecureRandom secureRandom = new SecureRandom();

    // 生成一个普通的随机数
    public static int generateOrdinaryRandomNumber(int bound) {
        if (bound <= 0) {
            throw new IllegalArgumentException("Bound must be positive");
        }
        return random.nextInt(bound);
    }

    // 生成一个密码学安全的随机数
    public static int generateSecureRandomNumber(int bound) {
        if (bound <= 0) {
            throw new IllegalArgumentException("Bound must be positive");
        }
        return secureRandom.nextInt(bound);
    }

    public static void main(String[] args) {
        System.out.println("Ordinary Random Number: " + generateOrdinaryRandomNumber(100));
        System.out.println("Secure Random Number: " + generateSecureRandomNumber(100));
    }
}