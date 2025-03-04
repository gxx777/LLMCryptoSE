import java.security.SecureRandom;

public class RandomExample2 {

    private SecureRandom random;

    public RandomExample2() {
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

    public byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    public static void main(String[] args) {
        RandomExample2 randomExample2 = new RandomExample2();
        System.out.println("Random int: " + randomExample2.generateRandomInt());
        System.out.println("Random double: " + randomExample2.generateRandomDouble());
        System.out.println("Random long: " + randomExample2.generateRandomLong());
        System.out.println("Random float: " + randomExample2.generateRandomFloat());
        System.out.println("Random boolean: " + randomExample2.generateRandomBoolean());
        System.out.println("Random bytes: " + randomExample2.generateRandomBytes(10));
    }
}