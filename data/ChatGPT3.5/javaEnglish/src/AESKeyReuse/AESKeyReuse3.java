import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESKeyReuse3 {
    private SecretKey secretKey;

    public AESKeyReuse3() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            this.secretKey = keyGenerator.generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String encryptMessage(String message) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String decryptMessage(String encryptedMessage) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        AESKeyReuse3 aesKeyReuse3 = new AESKeyReuse3();
        String message1 = "Hello, Participant 1!";
        String message2 = "Greetings, Participant 2!";
        String message3 = "Salutations, Participant 3!";

        String encryptedMessage1 = aesKeyReuse3.encryptMessage(message1);
        String encryptedMessage2 = aesKeyReuse3.encryptMessage(message2);
        String encryptedMessage3 = aesKeyReuse3.encryptMessage(message3);

        System.out.println("Encrypted Message 1: " + encryptedMessage1);
        System.out.println("Decrypted Message 1: " + aesKeyReuse3.decryptMessage(encryptedMessage1));

        System.out.println("Encrypted Message 2: " + encryptedMessage2);
        System.out.println("Decrypted Message 2: " + aesKeyReuse3.decryptMessage(encryptedMessage2));

        System.out.println("Encrypted Message 3: " + encryptedMessage3);
        System.out.println("Decrypted Message 3: " + aesKeyReuse3.decryptMessage(encryptedMessage3));
    }
}