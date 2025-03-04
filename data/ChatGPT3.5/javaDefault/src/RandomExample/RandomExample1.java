import java.util.Random;

public class RandomExample1 {
    public static void main(String[] args) {
        Random random = new Random();
        int randomNum = random.nextInt(100);
        System.out.println("Random number: " + randomNum);
    }
}