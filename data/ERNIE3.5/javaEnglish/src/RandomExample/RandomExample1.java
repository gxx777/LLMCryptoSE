import java.security.SecureRandom;

public class RandomExample1 {

    private static final SecureRandom random = new SecureRandom();

    public static int generateRandomInt(int min, int max) {
        if (min >= max) {
            throw new IllegalArgumentException("Min value must be less than max value");
        }

        return min + random.nextInt(max - min + 1);
    }

    public static double generateRandomDouble(double min, double max) {
        if (min >= max) {
            throw new IllegalArgumentException("Min value must be less than max value");
        }

        return min + random.nextDouble() * (max - min);
    }

    public static void main(String[] args) {
        int randomInt = generateRandomInt(1, 100);
        double randomDouble = generateRandomDouble(0.0, 1.0);

        System.out.println("Random Integer: " + randomInt);
        System.out.println("Random Double: " + randomDouble);
    }
}