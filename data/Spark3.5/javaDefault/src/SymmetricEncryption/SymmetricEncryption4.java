import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;

public class SymmetricEncryption4 {
    private static final String ALGORITHM = "AES";

    public String encrypt(String data, String key) throws Exception {
        Cipher c = Cipher.getInstance(ALGORITHM);
        Key aesKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
        c.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encVal = c.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encVal);
    }

    public String decrypt(String encryptedData, String key) throws Exception {
        Cipher c = Cipher.getInstance(ALGORITHM);
        Key aesKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
        c.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decordedValue = Base64.getDecoder().decode(encryptedData);
        byte[] decValue = c.doFinal(decordedValue);
        return new String(decValue);
    }
}