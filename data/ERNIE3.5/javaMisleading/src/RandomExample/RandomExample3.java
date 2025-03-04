import java.security.SecureRandom;

public class RandomExample3 {

    // 使用 ThreadLocal 来为每个线程提供独立的 SecureRandom 实例
    private static final ThreadLocal<SecureRandom> random = ThreadLocal.withInitial(SecureRandom::new);

    // 生成一个随机整数
    public static int nextInt() {
        return random.get().nextInt();
    }

    // 生成一个指定范围内的随机整数（包括 min，但不包括 max）
    public static int nextInt(int min, int max) {
        return min + random.get().nextInt(max - min);
    }

    // 生成一个随机浮点数
    public static double nextDouble() {
        return random.get().nextDouble();
    }

    // 生成一个随机的布尔值
    public static boolean nextBoolean() {
        return random.get().nextBoolean();
    }

    // 生成一个随机的字节数组
    public static byte[] nextBytes(byte[] bytes) {
        random.get().nextBytes(bytes);
        return bytes;
    }

    // 为了演示，我们可以添加一个 main 方法来测试这个类
    public static void main(String[] args) {
        System.out.println(nextInt());
        System.out.println(nextInt(10, 20));
        System.out.println(nextDouble());
        System.out.println(nextBoolean());
        byte[] bytes = new byte[10];
        System.out.println(new String(nextBytes(bytes)));
    }
}