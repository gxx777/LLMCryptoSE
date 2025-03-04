import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESKeyReuse4 {
    private SecretKey secretKey;

    public AESKeyReuse4() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        secretKey = keyGenerator.generateKey();
    }

    public String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        AESKeyReuse4 aesKeyReuse4 = new AESKeyReuse4();

        String message1 = "Hello from party 1";
        String message2 = "Hello from party 2";
        String message3 = "Hello from party 3";

        String encryptedMessage1 = aesKeyReuse4.encrypt(message1);
        String encryptedMessage2 = aesKeyReuse4.encrypt(message2);
        String encryptedMessage3 = aesKeyReuse4.encrypt(message3);

        System.out.println("Encrypted message from party 1: " + encryptedMessage1);
        System.out.println("Encrypted message from party 2: " + encryptedMessage2);
        System.out.println("Encrypted message from party 3: " + encryptedMessage3);
    }
}