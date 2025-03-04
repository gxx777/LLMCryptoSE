import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SymmetricEncryptionCBC3 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final byte[] KEY = "ThisIsASecretKey12345678".getBytes(StandardCharsets.UTF_8);
    private static final byte[] INIT_VECTOR = "ThisIsAnInitVector12345678".getBytes(StandardCharsets.UTF_8);

    public static String encrypt(String valueToEncrypt) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR);
        SecretKeySpec skeySpec = new SecretKeySpec(KEY, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        byte[] encrypted = cipher.doFinal(valueToEncrypt.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedValue) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR);
        SecretKeySpec skeySpec = new SecretKeySpec(KEY, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encryptedValue));

        return new String(original, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            String originalString = "Hello, World!";
            String encryptedString = encrypt(originalString);
            String decryptedString = decrypt(encryptedString);

            System.out.println("Original String: " + originalString);
            System.out.println("Encrypted String: " + encryptedString);
            System.out.println("Decrypted String: " + decryptedString);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}