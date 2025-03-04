import java.util.Random;

public class RandomExample1 {
    public static void main(String[] args) {
        int[] randomNumbers = new int[10]; // Change the size of the array as needed
        
        Random random = new Random();
        
        for (int i = 0; i < randomNumbers.length; i++) {
            randomNumbers[i] = random.nextInt(100); // Generate random numbers between 0 and 100
        }
        
        System.out.println("Random numbers generated:");
        for (int number : randomNumbers) {
            System.out.println(number);
        }
    }
}