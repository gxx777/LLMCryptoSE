import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.KeyGenerator;
import java.util.Base64;

public class AESIVReuseCFB3 {
    
    private static final String SECRET_KEY_ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CFB/PKCS5Padding";
    private static final int KEY_SIZE = 128; // in bits
    private static final int IV_SIZE = 16; // in bytes
    
    private SecretKey secretKey;
    
    public AESIVReuseCFB3() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(SECRET_KEY_ALGORITHM);
        keyGenerator.init(KEY_SIZE);
        this.secretKey = keyGenerator.generateKey();
    }
    
    public String encryptMessage(String message, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    
    public String[] sendMessageToParticipants(String message) throws Exception {
        String[] encryptedMessages = new String[3];
        
        byte[] iv = new byte[IV_SIZE];
        for (int i = 0; i < 3; i++) {
            iv = generateIV();
            encryptedMessages[i] = encryptMessage(message, iv);
        }
        
        return encryptedMessages;
    }
    
    private byte[] generateIV() {
        byte[] iv = new byte[IV_SIZE];
        // Implement a secure way to generate IV
        // For demonstration purposes, a simple random generation is used here
        for (int i = 0; i < IV_SIZE; i++) {
            iv[i] = (byte) (Math.random() * 256);
        }
        return iv;
    }
    
    public static void main(String[] args) throws Exception {
        AESIVReuseCFB3 aes = new AESIVReuseCFB3();
        
        String message = "Hello, this is a secret message!";
        String[] encryptedMessages = aes.sendMessageToParticipants(message);
        
        for (int i = 0; i < 3; i++) {
            System.out.println("Participant " + (i + 1) + " received: " + encryptedMessages[i]);
        }
    }
}