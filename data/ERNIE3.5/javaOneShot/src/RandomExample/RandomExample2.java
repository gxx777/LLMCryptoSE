import java.security.SecureRandom;
import java.util.Random;

public class RandomExample2 {

    private static final Random random = new Random();
    private static final SecureRandom secureRandom = new SecureRandom();

    // 使用普通的Random生成一个普通的随机数
    public static int generateOrdinaryRandomNumber(int bound) {
        if (bound <= 0) {
            throw new IllegalArgumentException("Bound must be a positive integer.");
        }
        return random.nextInt(bound);
    }

    // 使用SecureRandom生成一个密码学安全的随机数
    public static int generateSecureRandomNumber(int bound) {
        if (bound <= 0) {
            throw new IllegalArgumentException("Bound must be a positive integer.");
        }
        return secureRandom.nextInt(bound);
    }

    // 使用SecureRandom生成一个固定长度的随机字节数组
    public static byte[] generateSecureRandomBytes(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("Length must be a positive integer.");
        }
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    public static void main(String[] args) {
        // 测试普通的随机数生成
        System.out.println("Ordinary Random Number: " + generateOrdinaryRandomNumber(100));

        // 测试密码学安全的随机数生成
        System.out.println("Secure Random Number: " + generateSecureRandomNumber(100));

        // 测试生成随机字节数组
        byte[] randomBytes = generateSecureRandomBytes(16);
        System.out.println("Secure Random Bytes: " + new String(randomBytes));
    }
}