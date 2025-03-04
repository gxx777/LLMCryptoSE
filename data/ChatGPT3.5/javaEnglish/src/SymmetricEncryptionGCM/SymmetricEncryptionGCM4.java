import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionGCM4 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;

    public static String encrypt(String plaintext, String encryptionKey) throws Exception {
        byte[] iv = new byte[IV_LENGTH_BYTE];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        SecretKey secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

        byte[] cipherText = cipher.doFinal(plaintext.getBytes("UTF-8"));

        // Concatenate IV and cipher text
        byte[] ivAndCipherText = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, ivAndCipherText, 0, iv.length);
        System.arraycopy(cipherText, 0, ivAndCipherText, iv.length, cipherText.length);

        return Base64.getEncoder().encodeToString(ivAndCipherText);
    }

    public static String decrypt(String ivAndCipherText, String encryptionKey) throws Exception {
        byte[] ivAndCipherTextBytes = Base64.getDecoder().decode(ivAndCipherText);
        byte[] iv = new byte[IV_LENGTH_BYTE];
        byte[] cipherText = new byte[ivAndCipherTextBytes.length - IV_LENGTH_BYTE];
        System.arraycopy(ivAndCipherTextBytes, 0, iv, 0, IV_LENGTH_BYTE);
        System.arraycopy(ivAndCipherTextBytes, IV_LENGTH_BYTE, cipherText, 0, cipherText.length);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        SecretKey secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

        byte[] decryptedText = cipher.doFinal(cipherText);

        return new String(decryptedText, "UTF-8");
    }

    public static void main(String[] args) throws Exception {
        String encryptionKey = "secretEncryptionKey";
        String plaintext = "Hello, this is a secret message!";

        String encryptedText = encrypt(plaintext, encryptionKey);
        System.out.println("Encrypted text: " + encryptedText);

        String decryptedText = decrypt(encryptedText, encryptionKey);
        System.out.println("Decrypted text: " + decryptedText);
    }
}