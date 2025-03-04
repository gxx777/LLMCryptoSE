import java.security.SecureRandom;

public class RandomExample4 {
    private static final SecureRandom random = new SecureRandom();

    // 使用SecureRandom生成一个随机的int值
    public static int getRandomInt() {
        return random.nextInt();
    }

    // 使用SecureRandom生成一个指定范围内的随机int值
    public static int getRandomInt(int min, int max) {
        if (min >= max) {
            throw new IllegalArgumentException("min must be less than max");
        }
        return min + random.nextInt(max - min + 1);
    }

    // 使用SecureRandom生成一个随机的double值
    public static double getRandomDouble() {
        return random.nextDouble();
    }

    // 使用SecureRandom生成一个随机的boolean值
    public static boolean getRandomBoolean() {
        return random.nextBoolean();
    }

    // 使用SecureRandom生成一个随机的byte数组
    public static byte[] getRandomBytes(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    public static void main(String[] args) {
        System.out.println("Random Int: " + getRandomInt(0, 100));
        System.out.println("Random Double: " + getRandomDouble());
        System.out.println("Random Boolean: " + getRandomBoolean());
        System.out.println("Random Bytes: " + new String(getRandomBytes(10)));
    }
}