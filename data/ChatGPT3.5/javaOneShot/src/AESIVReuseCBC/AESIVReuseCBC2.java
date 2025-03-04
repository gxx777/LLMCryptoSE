import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCBC2 {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "CBC";
    private static final String PADDING = "PKCS5Padding";

    private byte[] key;
    private byte[] iv;

    public AESIVReuseCBC2(byte[] key, byte[] iv) {
        this.key = key;
        this.iv = iv;
    }

    public String encrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encrypted = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String decrypt(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(original);
    }

    public static void main(String[] args) throws Exception {
        // Generate random key and IV for each participant
        byte[] keyAlice = "keyAlice12345678".getBytes();
        byte[] ivAlice = "initialVectorAlice".getBytes();

        byte[] keyBob = "keyBob1234567890".getBytes();
        byte[] ivBob = "initialVectorBob123".getBytes();

        byte[] keyCharlie = "keyCharlie12345".getBytes();
        byte[] ivCharlie = "initialVectorCharlie".getBytes();

        // Alice sends a message to Bob
        AESIVReuseCBC2 aliceCipher = new AESIVReuseCBC2(keyAlice, ivAlice);
        String messageToBob = "Hello Bob!";
        String encryptedMessageToBob = aliceCipher.encrypt(messageToBob);
        System.out.println("Alice sends to Bob: " + encryptedMessageToBob);

        // Bob decrypts the message from Alice
        AESIVReuseCBC2 bobCipher = new AESIVReuseCBC2(keyBob, ivBob);
        String decryptedMessageFromAlice = bobCipher.decrypt(encryptedMessageToBob);
        System.out.println("Bob receives from Alice: " + decryptedMessageFromAlice);

        // Bob sends a message to Charlie
        String messageToCharlie = "Hi Charlie!";
        String encryptedMessageToCharlie = bobCipher.encrypt(messageToCharlie);
        System.out.println("Bob sends to Charlie: " + encryptedMessageToCharlie);

        // Charlie decrypts the message from Bob
        AESIVReuseCBC2 charlieCipher = new AESIVReuseCBC2(keyCharlie, ivCharlie);
        String decryptedMessageFromBob = charlieCipher.decrypt(encryptedMessageToCharlie);
        System.out.println("Charlie receives from Bob: " + decryptedMessageFromBob);
    }
}