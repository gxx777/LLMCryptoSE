import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;

public class SymmetricEncryptionGCM1 {

    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_NONCE_LENGTH = 12;
    private static final int ITERATION_COUNT = 10000;
    private static final int KEY_LENGTH = 256;

    public static byte[] encrypt(String plaintext, char[] password) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATION_COUNT, KEY_LENGTH);
        SecretKey secretKey = factory.generateSecret(spec);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[GCM_NONCE_LENGTH];
        random.nextBytes(iv);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

        byte[] encrypted = cipher.doFinal(plaintext.getBytes());
        byte[] ciphertext = new byte[salt.length + iv.length + encrypted.length];
        System.arraycopy(salt, 0, ciphertext, 0, salt.length);
        System.arraycopy(iv, 0, ciphertext, salt.length, iv.length);
        System.arraycopy(encrypted, 0, ciphertext, salt.length + iv.length, encrypted.length);

        return ciphertext;
    }

    public static String decrypt(byte[] ciphertext, char[] password) throws Exception {
        byte[] salt = new byte[16];
        byte[] iv = new byte[GCM_NONCE_LENGTH];
        byte[] encrypted = new byte[ciphertext.length - salt.length - iv.length];
        System.arraycopy(ciphertext, 0, salt, 0, salt.length);
        System.arraycopy(ciphertext, salt.length, iv, 0, iv.length);
        System.arraycopy(ciphertext, salt.length + iv.length, encrypted, 0, encrypted.length);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATION_COUNT, KEY_LENGTH);
        SecretKey secretKey = factory.generateSecret(spec);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted);
    }
}