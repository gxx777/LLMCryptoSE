import java.util.Random;

public class RandomExample3 {
    private static final Random random = new Random();

    // Method to generate a random number between a specified range
    public static int generateRandomNumber(int min, int max) {
        return random.nextInt((max - min) + 1) + min;
    }

    public static void main(String[] args) {
        int min = 1;
        int max = 100;

        // Generate and print a random number between 1 and 100
        int randomNumber = generateRandomNumber(min, max);
        System.out.println("Random number between " + min + " and " + max + ": " + randomNumber);
    }
}