import java.util.Random;

public class RandomExample4 {
    private Random random;

    public RandomExample4() {
        this.random = new Random();
    }

    public int getRandomNumber(int min, int max) {
        return random.nextInt((max - min) + 1) + min;
    }

    public static void main(String[] args) {
        RandomExample4 re = new RandomExample4();
        System.out.println("Random number between 10 and 20: " + re.getRandomNumber(10, 20));
    }
}