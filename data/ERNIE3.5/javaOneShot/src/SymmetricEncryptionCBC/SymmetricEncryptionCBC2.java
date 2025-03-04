import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;

public class SymmetricEncryptionCBC2 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final byte[] KEY = "ThisIsASecretKeyThisIsASecretKey".getBytes(StandardCharsets.UTF_8); // 256-bit key
    private static final byte[] INIT_VECTOR = "ThisIsAnInitializationVector".getBytes(StandardCharsets.UTF_8); // Initialization Vector

    // Encryption
    public static String encrypt(String valueToEnc) throws Exception {
        Key key = new SecretKeySpec(KEY, "AES");
        IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        byte[] encryptedValue = cipher.doFinal(valueToEnc.getBytes());
        return Base64.getEncoder().encodeToString(encryptedValue);
    }

    // Decryption
    public static String decrypt(String encryptedValue) throws Exception {
        Key key = new SecretKeySpec(KEY, "AES");
        IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        byte[] originalValue = cipher.doFinal(Base64.getDecoder().decode(encryptedValue));

        return new String(originalValue);
    }

    public static void main(String[] args) {
        try {
            String originalText = "This is a secret message!";
            String encryptedText = encrypt(originalText);
            String decryptedText = decrypt(encryptedText);

            System.out.println("Original Text: " + originalText);
            System.out.println("Encrypted Text: " + encryptedText);
            System.out.println("Decrypted Text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}