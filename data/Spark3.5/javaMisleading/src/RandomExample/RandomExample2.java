import java.util.Random;

public class RandomExample2 {
    private static final Random random = new Random();

    public static int generateRandomInt(int min, int max) {
        if (min >= max) {
            throw new IllegalArgumentException("Max must be greater than min");
        }

        return random.nextInt((max - min) + 1) + min;
    }

    public static void main(String[] args) {
        int min = 1;
        int max = 10;

        int randomNumber = generateRandomInt(min, max);
        System.out.println("Random number between " + min + " and " + max + ": " + randomNumber);
    }
}