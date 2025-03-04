import java.util.Random;

public class RandomExample1 {
    public static void main(String[] args) {
        Random random = new Random();
        int randomNumber = random.nextInt(); // 生成一个随机整数
        System.out.println("随机数：" + randomNumber);
    }
}