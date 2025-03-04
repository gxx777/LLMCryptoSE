import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Base64;

public class SymmetricEncryption4 {
    private static final String ALGORITHM = "AES";
    private static final String MD5_ALGORITHM = "MD5";

    public static String encrypt(String data, String key) throws Exception {
        byte[] keyBytes = generateKey(key).getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    public static String decrypt(String encryptedData, String key) throws Exception {
        byte[] keyBytes = generateKey(key).getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedData = cipher.doFinal(decodedData);
        return new String(decryptedData);
    }

    private static SecretKey generateKey(String key) throws Exception {
        MessageDigest md = MessageDigest.getInstance(MD5_ALGORITHM);
        md.update(key.getBytes());
        byte[] digest = md.digest();
        return new SecretKeySpec(digest, ALGORITHM);
    }
}