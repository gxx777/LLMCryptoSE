import java.security.SecureRandom;

public class RandomExample2 {
    private static final SecureRandom secureRandom = new SecureRandom();

    public static int generateRandomInt(int min, int max) {
        if (min >= max) {
            throw new IllegalArgumentException("Max must be greater than min");
        }

        return secureRandom.nextInt((max - min) + 1) + min;
    }

    public static void main(String[] args) {
        int randomInt = generateRandomInt(1, 10);
        System.out.println("Random integer between 1 and 10: " + randomInt);
    }
}