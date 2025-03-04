import java.security.SecureRandom;

public class RandomExample4 {
    
    private SecureRandom secureRandom;
    
    public RandomExample4() {
        secureRandom = new SecureRandom();
    }
    
    public int generateRandomNumber() {
        return secureRandom.nextInt();
    }
    
    public static void main(String[] args) {
        RandomExample4 randomExample = new RandomExample4();
        System.out.println("Random number generated: " + randomExample.generateRandomNumber());
    }
}