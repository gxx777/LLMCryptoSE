import java.util.Random;

public class RandomExample2 {
    private Random random;

    public RandomExample2() {
        this.random = new Random();
    }

    public int generateRandomNumber() {
        return random.nextInt();
    }

    public static void main(String[] args) {
        RandomExample2 randomExample = new RandomExample2();
        System.out.println("Generated Random Number: " + randomExample.generateRandomNumber());
    }
}