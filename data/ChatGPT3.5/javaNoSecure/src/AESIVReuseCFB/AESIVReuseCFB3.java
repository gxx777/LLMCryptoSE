import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;

public class AESIVReuseCFB3 {

    public static void main(String[] args) throws Exception {
        // Generate encryption key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        SecretKey key = keygen.generateKey();

        // Generate IV
        byte[] iv = new byte[16];
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Initialize Cipher in CFB mode with key and IV
        Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        // Simulate three different parties
        String party1Message = "Hello from Party 1";
        String party2Message = "Hello from Party 2";
        String party3Message = "Hello from Party 3";

        // Encrypt and send messages
        byte[] party1Encrypted = cipher.update(party1Message.getBytes());
        byte[] party2Encrypted = cipher.update(party2Message.getBytes());
        byte[] party3Encrypted = cipher.update(party3Message.getBytes());

        // Print encrypted messages
        System.out.println("Party 1 encrypted message: " + Base64.getEncoder().encodeToString(party1Encrypted));
        System.out.println("Party 2 encrypted message: " + Base64.getEncoder().encodeToString(party2Encrypted));
        System.out.println("Party 3 encrypted message: " + Base64.getEncoder().encodeToString(party3Encrypted));
    }
}