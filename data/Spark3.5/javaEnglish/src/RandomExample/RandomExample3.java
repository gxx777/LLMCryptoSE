import java.util.Random;

public class RandomExample3 {
    public static void main(String[] args) {
        Random random = new Random();
        int randomNumber = random.nextInt();
        System.out.println("随机数： " + randomNumber);
    }
}