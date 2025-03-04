import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SymmetricEncryptionCBC2 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final byte[] KEY = "ThisIsASecretKeyThisIsASecretKey".getBytes(StandardCharsets.UTF_8);
    private static final byte[] INIT_VECTOR = "RandomInitVector".getBytes(StandardCharsets.UTF_8);

    public static String encrypt(String valueToEncrypt) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR);
        SecretKeySpec skeySpec = new SecretKeySpec(KEY, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        byte[] encrypted = cipher.doFinal(valueToEncrypt.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedValue) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR);
        SecretKeySpec skeySpec = new SecretKeySpec(KEY, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encryptedValue));

        return new String(original);
    }

    public static void main(String[] args) {
        try {
            String originalString = "Hello, World!";
            System.out.println("Original String: " + originalString);

            String encryptedString = encrypt(originalString);
            System.out.println("Encrypted String: " + encryptedString);

            String decryptedString = decrypt(encryptedString);
            System.out.println("Decrypted String: " + decryptedString);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}