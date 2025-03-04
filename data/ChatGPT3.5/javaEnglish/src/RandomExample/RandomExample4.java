import java.util.Random;

public class RandomExample4 {
    
    public static void main(String[] args) {
        RandomExample4 randomExample = new RandomExample4();
        for (int i = 0; i < 5; i++) {
            System.out.println("Random number " + (i + 1) + ": " + randomExample.generateRandomNumber());
        }
    }
    
    public int generateRandomNumber() {
        Random random = new Random();
        return random.nextInt();
    }
}