import java.security.SecureRandom;

public class RandomExample1 {
    public static void main(String[] args) {
        SecureRandom secureRandom = new SecureRandom();
        int randomNum = secureRandom.nextInt(100);
        System.out.println("Random number: " + randomNum);
    }
}