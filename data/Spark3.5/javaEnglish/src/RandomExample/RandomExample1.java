import java.util.Random;

public class RandomExample1 {
    public static void main(String[] args) {
        // Create a new instance of the Random class
        Random rand = new Random();

        // Generate a random integer between 0 and 99
        int randomInt = rand.nextInt(100);
        System.out.println("Random Integer: " + randomInt);

        // Generate a random double between 0.0 and 1.0
        double randomDouble = rand.nextDouble();
        System.out.println("Random Double: " + randomDouble);

        // Generate a random boolean value
        boolean randomBoolean = rand.nextBoolean();
        System.out.println("Random Boolean: " + randomBoolean);
    }
}