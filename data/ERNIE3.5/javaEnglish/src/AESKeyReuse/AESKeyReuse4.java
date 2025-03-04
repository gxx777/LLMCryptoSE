import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESKeyReuse4 {
    private static final String ALGORITHM = "AES";
    private static final int KEY_SIZE = 128;

    private SecretKey secretKey;

    public AESKeyReuse4() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(KEY_SIZE, new SecureRandom());
        secretKey = keyGenerator.generateKey();
    }

    public String encryptMessage(String message, String participantKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKey participantSecretKey = new SecretKeySpec(participantKey.getBytes(), ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, participantSecretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decryptMessage(String encryptedMessage, String participantKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKey participantSecretKey = new SecretKeySpec(participantKey.getBytes(), ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, participantSecretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        AESKeyReuse4 aesKeyReuse = new AESKeyReuse4();

        String message = "Hello, World!";
        String participant1Key = "Participant1Key";
        String participant2Key = "Participant2Key";
        String participant3Key = "Participant3Key";

        // Encrypt messages for each participant
        String encryptedMessage1 = aesKeyReuse.encryptMessage(message, participant1Key);
        String encryptedMessage2 = aesKeyReuse.encryptMessage(message, participant2Key);
        String encryptedMessage3 = aesKeyReuse.encryptMessage(message, participant3Key);

        System.out.println("Encrypted message for Participant 1: " + encryptedMessage1);
        System.out.println("Encrypted message for Participant 2: " + encryptedMessage2);
        System.out.println("Encrypted message for Participant 3: " + encryptedMessage3);

        // Decrypt messages for each participant
        String decryptedMessage1 = aesKeyReuse.decryptMessage(encryptedMessage1, participant1Key);
        String decryptedMessage2 = aesKeyReuse.decryptMessage(encryptedMessage2, participant2Key);
        String decryptedMessage3 = aesKeyReuse.decryptMessage(encryptedMessage3, participant3Key);

        System.out.println("Decrypted message for Participant 1: " + decryptedMessage1);
        System.out.println("Decrypted message for Participant 2: " + decryptedMessage2);
        System.out.println("Decrypted message for Participant 3: " + decryptedMessage3);
    }
}