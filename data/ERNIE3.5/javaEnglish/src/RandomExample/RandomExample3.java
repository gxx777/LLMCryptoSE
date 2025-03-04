import java.util.Random;

public class RandomExample3 {
    private Random random;

    public RandomExample3() {
        this.random = new Random();
    }

    /**
     * Generates a random integer between the given min and max values (inclusive).
     *
     * @param min The minimum value (inclusive).
     * @param max The maximum value (inclusive).
     * @return A random integer between min and max.
     */
    public int generateRandomInt(int min, int max) {
        if (min > max) {
            throw new IllegalArgumentException("Min value must be less than or equal to max value.");
        }
        return min + random.nextInt(max - min + 1);
    }

    /**
     * Generates a random double between the given min and max values (inclusive).
     *
     * @param min The minimum value (inclusive).
     * @param max The maximum value (inclusive).
     * @return A random double between min and max.
     */
    public double generateRandomDouble(double min, double max) {
        if (min > max) {
            throw new IllegalArgumentException("Min value must be less than or equal to max value.");
        }
        return min + random.nextDouble() * (max - min);
    }

    public static void main(String[] args) {
        RandomExample3 randomExample = new RandomExample3();

        // Generate a random integer between 1 and 10
        int randomInt = randomExample.generateRandomInt(1, 10);
        System.out.println("Random Integer: " + randomInt);

        // Generate a random double between 0.0 and 1.0
        double randomDouble = randomExample.generateRandomDouble(0.0, 1.0);
        System.out.println("Random Double: " + randomDouble);
    }
}