import java.security.SecureRandom;

public class RandomExample4 {
    private SecureRandom secureRandom;

    public RandomExample4() {
        this.secureRandom = new SecureRandom();
    }

    public int generateRandomNumber(int bound) {
        return secureRandom.nextInt(bound);
    }
}