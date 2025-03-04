import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseOFB1 {

    public static void main(String[] args) throws Exception {
        String message1 = "Hello Alice!";
        String message2 = "Hello Bob!";
        String message3 = "Hello Charlie!";

        // Generate AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();

        // Create initialization vector
        byte[] iv = new byte[16];
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Create AES cipher in OFB mode
        Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");

        // Encrypt and send message to Alice
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedMessage1 = cipher.doFinal(message1.getBytes());
        // Send encrypted message1

        // Encrypt and send message to Bob
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedMessage2 = cipher.doFinal(message2.getBytes());
        // Send encrypted message2

        // Encrypt and send message to Charlie
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedMessage3 = cipher.doFinal(message3.getBytes());
        // Send encrypted message3
    }
}