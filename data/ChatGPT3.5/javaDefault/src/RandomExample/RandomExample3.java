import java.security.SecureRandom;

public class RandomExample3 {
    
    public static void main(String[] args) {
        SecureRandom random = new SecureRandom();
        
        // 生成一个随机整数
        int randomInt = random.nextInt();
        System.out.println("随机整数: " + randomInt);
        
        // 生成一个0到100之间的随机整数
        int randomIntInRange = random.nextInt(101);
        System.out.println("0到100之间的随机整数: " + randomIntInRange);
        
        // 生成一个随机双精度浮点数
        double randomDouble = random.nextDouble();
        System.out.println("随机双精度浮点数: " + randomDouble);
        
        // 生成一个随机布尔值
        boolean randomBoolean = random.nextBoolean();
        System.out.println("随机布尔值: " + randomBoolean);
    }
}