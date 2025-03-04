import java.util.Random;

public class RandomExample2 {
    private Random random;

    public RandomExample2() {
        random = new Random();
    }

    public int generateRandomNumber(int min, int max) {
        return random.nextInt(max - min + 1) + min;
    }

    public static void main(String[] args) {
        RandomExample2 randomExample = new RandomExample2();
        int randomNumber = randomExample.generateRandomNumber(1, 100);
        System.out.println("Generated random number: " + randomNumber);
    }
}