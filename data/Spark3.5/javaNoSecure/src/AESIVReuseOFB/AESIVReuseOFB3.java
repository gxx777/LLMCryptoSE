import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseOFB3 {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/OFB/PKCS5Padding";
    private static final int KEY_SIZE = 128;
    private static final int IV_SIZE = 16;

    private SecretKey secretKey;
    private IvParameterSpec ivParameterSpec;

    public AESIVReuseOFB3() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(KEY_SIZE);
        secretKey = keyGenerator.generateKey();

        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        ivParameterSpec = new IvParameterSpec(iv);
    }

    public String encryptMessage(String message) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedMessage);
    }

    public void sendMessageToParty1(String message) {
        // Send the encrypted message to Party 1
    }

    public void sendMessageToParty2(String message) {
        // Send the encrypted message to Party 2
    }

    public void sendMessageToParty3(String message) {
        // Send the encrypted message to Party 3
    }

    public static void main(String[] args) {
        try {
            AESIVReuseOFB3 aesIVReuseOFB3 = new AESIVReuseOFB3();
            String message = "Hello, this is a secret message!";
            String encryptedMessage = aesIVReuseOFB3.encryptMessage(message);
            aesIVReuseOFB3.sendMessageToParty1(encryptedMessage);
            aesIVReuseOFB3.sendMessageToParty2(encryptedMessage);
            aesIVReuseOFB3.sendMessageToParty3(encryptedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}