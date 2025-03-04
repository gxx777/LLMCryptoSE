import java.security.SecureRandom;

public class RandomExample4 {

    private static final SecureRandom secureRandom = new SecureRandom();

    // 生成随机整数
    public static int generateRandomInt(int min, int max) {
        if (min >= max) {
            throw new IllegalArgumentException("min must be less than max");
        }
        return min + secureRandom.nextInt(max - min + 1);
    }

    // 生成随机字节
    public static byte[] generateRandomBytes(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("length must be positive");
        }
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    public static void main(String[] args) {
        // 生成一个介于1和100之间的随机整数
        int randomInt = generateRandomInt(1, 100);
        System.out.println("Random Integer: " + randomInt);

        // 生成一个长度为10的随机字节数组
        byte[] randomBytes = generateRandomBytes(10);
        System.out.println("Random Bytes: " + new String(randomBytes));
    }
}