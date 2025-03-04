import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

public class AESIVReuseCFB4 {
    private static final String ALGORITHM = "AES/CFB8/NoPadding";
    private static final byte[] IV = new byte[16]; // 初始化向量

    public static byte[] encrypt(String key, byte[] plaintext) throws GeneralSecurityException {
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(IV));
        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(String key, byte[] ciphertext) throws GeneralSecurityException {
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(IV));
        return cipher.doFinal(ciphertext);
    }
}