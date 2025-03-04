import java.security.SecureRandom;

public class RandomExample2 {
    
    private SecureRandom random;

    public RandomExample2() {
        this.random = new SecureRandom();
    }

    public int generateRandomNumber() {
        return random.nextInt();
    }

    public double generateRandomDouble() {
        return random.nextDouble();
    }

    public long generateRandomLong() {
        return random.nextLong();
    }

    public boolean generateRandomBoolean() {
        return random.nextBoolean();
    }

    public static void main(String[] args) {
        RandomExample2 randomExample = new RandomExample2();
        System.out.println("Random Integer: " + randomExample.generateRandomNumber());
        System.out.println("Random Double: " + randomExample.generateRandomDouble());
        System.out.println("Random Long: " + randomExample.generateRandomLong());
        System.out.println("Random Boolean: " + randomExample.generateRandomBoolean());
    }
}