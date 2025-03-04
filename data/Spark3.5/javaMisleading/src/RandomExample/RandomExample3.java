import java.util.Random;

public class RandomExample3 {
    private Random random;

    public RandomExample3() {
        this.random = new Random();
    }

    public int generateRandomNumber(int bound) {
        return random.nextInt(bound);
    }

    public static void main(String[] args) {
        RandomExample3 randomExample = new RandomExample3();
        int randomNumber = randomExample.generateRandomNumber(100);
        System.out.println("生成的随机数为： " + randomNumber);
    }
}