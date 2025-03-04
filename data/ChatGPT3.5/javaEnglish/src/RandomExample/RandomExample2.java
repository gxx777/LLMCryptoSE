import java.util.Random;

public class RandomExample2 {
    
    public static void main(String[] args) {
        Random random = new Random();
        
        // Generating and printing random integers
        System.out.println("Random Integer: " + random.nextInt());
        
        // Generating and printing random doubles
        System.out.println("Random Double: " + random.nextDouble());
        
        // Generating and printing random booleans
        System.out.println("Random Boolean: " + random.nextBoolean());
        
        // Generating and printing random floats
        System.out.println("Random Float: " + random.nextFloat());
    }
}