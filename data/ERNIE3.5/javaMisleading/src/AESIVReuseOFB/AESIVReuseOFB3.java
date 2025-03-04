import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseOFB3 {

    private static final String ALGORITHM = "AES/OFB/NoPadding";
    private static final int KEY_SIZE = 128;

    public static void main(String[] args) throws Exception {
        String[] messages = {"Message 1", "Message 2", "Message 3"};
        String key = generateKey();
        String iv = generateIV();

        for (String message : messages) {
            String encrypted = encrypt(message, key, iv);
            System.out.println("Encrypted: " + encrypted);

            // Reusing the IV for the next message (NOT RECOMMENDED IN REAL WORLD SCENARIOS)
            iv = encrypted.substring(encrypted.length() - 16);
        }
    }

    private static String generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        SecretKey secretKey = keyGenerator.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    private static String generateIV() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
    }

    private static String encrypt(String message, String key, String iv) throws Exception {
        SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode(key), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(Base64.getDecoder().decode(iv));

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        byte[] encrypted = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
}