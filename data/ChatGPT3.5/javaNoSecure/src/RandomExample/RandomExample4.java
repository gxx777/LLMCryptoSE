import java.util.Random;

public class RandomExample4 {

    private Random random;

    public RandomExample4() {
        random = new Random();
    }

    public int generateRandomInt(int min, int max) {
        return random.nextInt(max - min + 1) + min;
    }

    public double generateRandomDouble(double min, double max) {
        return min + (max - min) * random.nextDouble();
    }

    public static void main(String[] args) {
        RandomExample4 randomExample = new RandomExample4();

        int randomInt = randomExample.generateRandomInt(1, 100);
        System.out.println("Random Integer between 1 and 100: " + randomInt);

        double randomDouble = randomExample.generateRandomDouble(1.0, 10.0);
        System.out.println("Random Double between 1.0 and 10.0: " + randomDouble);
    }
}