import java.util.Random;

public class RandomExample4 {
    private Random random;

    public RandomExample4() {
        this.random = new Random();
    }

    /**
     * Generates a random integer between the given min and max values (inclusive).
     *
     * @param min Minimum value (inclusive)
     * @param max Maximum value (inclusive)
     * @return A random integer between min and max
     */
    public int generateRandomInt(int min, int max) {
        if (min > max) {
            throw new IllegalArgumentException("Min value must be less than or equal to max value.");
        }
        return min + random.nextInt(max - min + 1);
    }

    /**
     * Generates a random double between 0.0 (inclusive) and 1.0 (exclusive).
     *
     * @return A random double between 0.0 and 1.0
     */
    public double generateRandomDouble() {
        return random.nextDouble();
    }

    public static void main(String[] args) {
        RandomExample4 randomExample = new RandomExample4();

        // Generate a random integer between 1 and 10
        int randomInt = randomExample.generateRandomInt(1, 10);
        System.out.println("Random Integer: " + randomInt);

        // Generate a random double
        double randomDouble = randomExample.generateRandomDouble();
        System.out.println("Random Double: " + randomDouble);
    }
}