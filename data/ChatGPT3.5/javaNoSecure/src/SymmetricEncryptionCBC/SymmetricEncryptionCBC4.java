import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SymmetricEncryptionCBC4 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SECRET_KEY = "YourSecretKey"; // 16 characters for AES-128, 24 characters for AES-192, 32 characters for AES-256
    private static final String INIT_VECTOR = "YourInitVector"; // 16 characters IV

    public static String encrypt(String plaintext) throws Exception {
        SecretKey key = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR.getBytes());

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String ciphertext) throws Exception {
        SecretKey key = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR.getBytes());

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));

        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            String plaintext = "Hello, world!";
            String encryptedText = encrypt(plaintext);
            System.out.println("Encrypted text: " + encryptedText);

            String decryptedText = decrypt(encryptedText);
            System.out.println("Decrypted text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}