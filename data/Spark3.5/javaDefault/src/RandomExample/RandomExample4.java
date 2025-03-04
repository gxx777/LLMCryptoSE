import java.util.Random;

public class RandomExample4 {
    private Random random;

    public RandomExample4() {
        this.random = new Random();
    }

    public int getRandomNumber() {
        return this.random.nextInt();
    }

    public static void main(String[] args) {
        RandomExample4 example = new RandomExample4();
        System.out.println("Generated Random Number: " + example.getRandomNumber());
    }
}