import java.security.SecureRandom;

public class RandomExample3 {

    private SecureRandom random;

    public RandomExample3() {
        random = new SecureRandom();
    }

    public int generateRandomInt() {
        return random.nextInt();
    }

    public double generateRandomDouble() {
        return random.nextDouble();
    }

    public long generateRandomLong() {
        return random.nextLong();
    }

    public float generateRandomFloat() {
        return random.nextFloat();
    }

    public boolean generateRandomBoolean() {
        return random.nextBoolean();
    }

}