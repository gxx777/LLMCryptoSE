import java.security.SecureRandom;

public class RandomExample3 {
    private static final SecureRandom secureRandom = new SecureRandom();

    public static int generateRandomNumber(int n) {
        return secureRandom.nextInt(n);
    }
}