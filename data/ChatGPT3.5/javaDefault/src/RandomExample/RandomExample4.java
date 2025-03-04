import java.security.SecureRandom;

public class RandomExample4 {

    private SecureRandom secureRandom;

    public RandomExample4() {
        secureRandom = new SecureRandom();
    }

    public int generateRandomNumber(int min, int max) {
        return secureRandom.nextInt(max - min + 1) + min;
    }

    public static void main(String[] args) {
        RandomExample4 randomExample = new RandomExample4();

        // 生成一个介于1和100之间的随机数
        int randomNumber = randomExample.generateRandomNumber(1, 100);
        System.out.println("Random number: " + randomNumber);
    }
}