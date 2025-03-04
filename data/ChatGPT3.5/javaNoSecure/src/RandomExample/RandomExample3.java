import java.util.Random;

public class RandomExample3 {

    public static void main(String[] args) {
        Random random = new Random();
        
        // 生成一个随机整数
        int randomNumber = random.nextInt();
        System.out.println("随机整数: " + randomNumber);
        
        // 生成一个范围在0到99的随机整数
        int randomInRange = random.nextInt(100);
        System.out.println("0到99的随机整数: " + randomInRange);
        
        // 生成一个随机浮点数
        double randomDouble = random.nextDouble();
        System.out.println("随机浮点数: " + randomDouble);
    }
}