import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SymmetricEncryptionCBC4 {
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SECRET_KEY = "mySuperSecretKey"; // 16 characters long
    private static final String IV = "initvect"; // 8 characters long

    public String encrypt(String data) throws Exception {
        Cipher c = Cipher.getInstance(ALGORITHM);
        SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        IvParameterSpec iv = new IvParameterSpec(IV.getBytes());
        c.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encVal = c.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encVal);
    }

    public String decrypt(String encryptedData) throws Exception {
        Cipher c = Cipher.getInstance(ALGORITHM);
        SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        IvParameterSpec iv = new IvParameterSpec(IV.getBytes());
        c.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decordedValue = Base64.getDecoder().decode(encryptedData);
        byte[] decValue = c.doFinal(decordedValue);
        return new String(decValue);
    }
}