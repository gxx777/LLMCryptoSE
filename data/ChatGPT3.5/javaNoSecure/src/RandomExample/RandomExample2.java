import java.util.Random;

public class RandomExample2 {

    private Random random;

    public RandomExample2() {
        this.random = new Random();
    }

    public int generateRandomInt() {
        return random.nextInt();
    }

    public double generateRandomDouble() {
        return random.nextDouble();
    }

    public boolean generateRandomBoolean() {
        return random.nextBoolean();
    }

    public float generateRandomFloat() {
        return random.nextFloat();
    }

    public long generateRandomLong() {
        return random.nextLong();
    }

    public static void main(String[] args) {
        RandomExample2 example = new RandomExample2();

        System.out.println("Random int: " + example.generateRandomInt());
        System.out.println("Random double: " + example.generateRandomDouble());
        System.out.println("Random boolean: " + example.generateRandomBoolean());
        System.out.println("Random float: " + example.generateRandomFloat());
        System.out.println("Random long: " + example.generateRandomLong());
    }
}