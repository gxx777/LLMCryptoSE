import java.security.SecureRandom;

public class RandomExample4 {

    private SecureRandom secureRandom;

    public RandomExample4() {
        secureRandom = new SecureRandom();
    }

    public int generateRandomNumber(int min, int max) {
        return secureRandom.nextInt(max - min + 1) + min;
    }

    public double generateRandomDouble() {
        return secureRandom.nextDouble();
    }

    public boolean generateRandomBoolean() {
        return secureRandom.nextBoolean();
    }

    public long generateRandomLong() {
        return secureRandom.nextLong();
    }

    public float generateRandomFloat() {
        return secureRandom.nextFloat();
    }

    public static void main(String[] args) {
        RandomExample4 randomExample = new RandomExample4();

        System.out.println("Random Number between 1 and 100: " + randomExample.generateRandomNumber(1, 100));
        System.out.println("Random Double: " + randomExample.generateRandomDouble());
        System.out.println("Random Boolean: " + randomExample.generateRandomBoolean());
        System.out.println("Random Long: " + randomExample.generateRandomLong());
        System.out.println("Random Float: " + randomExample.generateRandomFloat());
    }
}