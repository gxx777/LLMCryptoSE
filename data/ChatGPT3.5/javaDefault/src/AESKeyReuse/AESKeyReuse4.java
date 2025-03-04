import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class AESKeyReuse4 {

    public static void main(String[] args) throws Exception {
        // Generate AES key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey aesKey = keyGenerator.generateKey();

        // Generate RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair rsaKeyPair = keyPairGenerator.generateKeyPair();

        // Encrypt message for participant A using AES key
        Cipher aesCipher1 = Cipher.getInstance("AES");
        aesCipher1.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedMsg1 = aesCipher1.doFinal("Message for participant A".getBytes());
        System.out.println("Encrypted message for participant A: " + new String(encryptedMsg1));

        // Encrypt message for participant B using AES key
        Cipher aesCipher2 = Cipher.getInstance("AES");
        aesCipher2.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedMsg2 = aesCipher2.doFinal("Message for participant B".getBytes());
        System.out.println("Encrypted message for participant B: " + new String(encryptedMsg2));

        // Encrypt message for participant C using RSA public key
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic());
        byte[] encryptedMsg3 = rsaCipher.doFinal("Message for participant C".getBytes());
        System.out.println("Encrypted message for participant C: " + new String(encryptedMsg3));
    }
}