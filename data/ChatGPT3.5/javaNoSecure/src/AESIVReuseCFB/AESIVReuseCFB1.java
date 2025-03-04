import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.Security;

public class AESIVReuseCFB1 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CFB/PKCS5Padding";

    private static final String IV = "1234567890123456"; // IV should be unique for each message

    public static void main(String[] args) {
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            // Create secret key
            Key key = new SecretKeySpec("secretKey".getBytes(), ALGORITHM);

            // Create cipher
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes()));

            // Encrypt message for participant 1
            String message1 = "Message for participant 1";
            byte[] encryptedMessage1 = cipher.doFinal(message1.getBytes());
            System.out.println("Encrypted message for participant 1: " + new String(encryptedMessage1));

            // Encrypt message for participant 2
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes()));
            String message2 = "Message for participant 2";
            byte[] encryptedMessage2 = cipher.doFinal(message2.getBytes());
            System.out.println("Encrypted message for participant 2: " + new String(encryptedMessage2));

            // Encrypt message for participant 3
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes()));
            String message3 = "Message for participant 3";
            byte[] encryptedMessage3 = cipher.doFinal(message3.getBytes());
            System.out.println("Encrypted message for participant 3: " + new String(encryptedMessage3));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}