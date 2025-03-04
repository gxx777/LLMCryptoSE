import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

public class AESKeyReuse4 {
    private SecretKey secretKey;

    public AESKeyReuse4() throws Exception {
        // Generate a new AES key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // for example
        secretKey = keyGenerator.generateKey();
    }

    public String encrypt(String plainText) throws Exception {
        // Create a new cipher and initialize it with the secret key
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Encrypt the plain text
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());

        // Convert the encrypted bytes to a string
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}