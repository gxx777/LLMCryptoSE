import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SymmetricEncryptionGCM4 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128; // Length of authentication tag in bits
    private static final byte[] KEY = "MySuperSecretKey".getBytes(StandardCharsets.UTF_8); // Replace with a secure key
    private static final byte[] NONCE = new byte[12]; // Replace with a random nonce for each encryption operation

    public static String encrypt(String plaintext) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, NONCE);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public static String decrypt(String ciphertext) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] bytes = Base64.getDecoder().decode(ciphertext);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, NONCE);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);

        byte[] plaintext = cipher.doFinal(bytes);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            String plaintext = "Hello, World!";
            String ciphertext = encrypt(plaintext);
            String decryptedtext = decrypt(ciphertext);

            System.out.println("Plaintext: " + plaintext);
            System.out.println("Ciphertext: " + ciphertext);
            System.out.println("Decryptedtext: " + decryptedtext);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}