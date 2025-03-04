import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

public class AESIVReuseOFB4 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/OFB8/NoPadding";
    private static final int KEY_SIZE = 128;
    private static final int IV_SIZE = 128;

    public static void main(String[] args) throws Exception {
        String message = "Hello, World!";
        String password = "ThisIsASecret";

        SecretKey key = generateSecretKey(password);
        IvParameterSpec iv = generateIV();

        String encryptedMessage = encrypt(message, key, iv);
        System.out.println("Encrypted message: " + encryptedMessage);

        String decryptedMessage = decrypt(encryptedMessage, key, iv);
        System.out.println("Decrypted message: " + decryptedMessage);
    }

    private static SecretKey generateSecretKey(String password) throws Exception {
        byte[] salt = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);

        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, KEY_SIZE);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
        byte[] secretKeyBytes = factory.generateSecret(spec).getEncoded();

        return new SecretKeySpec(secretKeyBytes, 0, KEY_SIZE / 8, ALGORITHM);
    }

    private static IvParameterSpec generateIV() {
        byte[] ivBytes = new byte[IV_SIZE / 8];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivBytes);

        return new IvParameterSpec(ivBytes);
    }

    private static String encrypt(String message, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String encryptedMessage, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}