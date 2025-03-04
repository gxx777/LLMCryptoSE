import java.util.Random;

public class RandomExample1 {

    public static void main(String[] args) {
        Random random = new Random();
        int randomNumber = random.nextInt();
        System.out.println("Random number: " + randomNumber);
    }
}