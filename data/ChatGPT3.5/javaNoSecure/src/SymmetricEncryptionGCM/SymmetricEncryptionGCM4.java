import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionGCM4 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 256;
    private static final int IV_SIZE = 96;
    private static final int TAG_SIZE = 128;

    public static String encrypt(String plaintext, String key) throws Exception {
        byte[] iv = generateRandomBytes(IV_SIZE / 8);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_SIZE, iv);

        SecretKey secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);

        return Base64.getEncoder().encodeToString(result);
    }

    public static String decrypt(String ciphertext, String key) throws Exception {
        byte[] data = Base64.getDecoder().decode(ciphertext);
        byte[] iv = new byte[IV_SIZE / 8];
        System.arraycopy(data, 0, iv, 0, iv.length);
        byte[] encryptedData = new byte[data.length - iv.length];
        System.arraycopy(data, iv.length, encryptedData, 0, encryptedData.length);

        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_SIZE, iv);

        SecretKey secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

        byte[] plaintext = cipher.doFinal(encryptedData);
        return new String(plaintext);
    }

    private static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    public static void main(String[] args) {
        try {
            String key = "ThisIsASecretKey123";
            String plaintext = "Hello, world!";
            System.out.println("Plain text: " + plaintext);

            String ciphertext = encrypt(plaintext, key);
            System.out.println("Encrypted text: " + ciphertext);

            String decryptedText = decrypt(ciphertext, key);
            System.out.println("Decrypted text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}