import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SymmetricEncryptionCFB4 {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "CFB";
    private static final String PADDING = "NoPadding";
    private static final int BLOCK_SIZE = 4; // Set block size to 4 for CFB mode

    private static final String KEY = "0123456789abcdef"; // 16-byte key
    private static final String IV = "fedcba9876543210"; // 16-byte initialization vector

    public static String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
        SecretKeySpec key = new SecretKeySpec(KEY.getBytes(), ALGORITHM);
        IvParameterSpec iv = new IvParameterSpec(IV.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
        SecretKeySpec key = new SecretKeySpec(KEY.getBytes(), ALGORITHM);
        IvParameterSpec iv = new IvParameterSpec(IV.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            String plaintext = "Hello, World!";
            String encrypted = encrypt(plaintext);
            System.out.println("Encrypted: " + encrypted);
            String decrypted = decrypt(encrypted);
            System.out.println("Decrypted: " + decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}