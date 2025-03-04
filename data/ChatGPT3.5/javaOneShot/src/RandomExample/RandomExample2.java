import java.security.SecureRandom;

public class RandomExample2 {
    
    private SecureRandom secureRandom;

    public RandomExample2() {
        secureRandom = new SecureRandom();
    }

    public int getRandomNumber() {
        return secureRandom.nextInt();
    }

    public static void main(String[] args) {
        RandomExample2 randomExample = new RandomExample2();
        System.out.println("Random Number: " + randomExample.getRandomNumber());
    }
}