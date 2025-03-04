import java.security.SecureRandom;

public class RandomExample3 {
    
    public static void main(String[] args) {
        SecureRandom random = new SecureRandom();
        
        // Generate a random integer
        int randomNumber = random.nextInt();
        System.out.println("Random Integer: " + randomNumber);
        
        // Generate a random double
        double randomDouble = random.nextDouble();
        System.out.println("Random Double: " + randomDouble);
        
        // Generate a random boolean
        boolean randomBoolean = random.nextBoolean();
        System.out.println("Random Boolean: " + randomBoolean);
        
        // Generate a random byte array
        byte[] randomBytes = new byte[10];
        random.nextBytes(randomBytes);
        System.out.print("Random Bytes: ");
        for (byte b : randomBytes) {
            System.out.print(b + " ");
        }
        System.out.println();
    }
}