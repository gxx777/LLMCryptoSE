import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR4 {
    private static final String AES = "AES";
    private static final String AES_CTR_NOPADDING = "AES/CTR/NoPadding";
    private static final int IV_SIZE = 16;

    public static String encrypt(String key, String value) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), AES);
            Cipher cipher = Cipher.getInstance(AES_CTR_NOPADDING);

            // 生成随机的初始向量 (IV)
            byte[] iv = new byte[IV_SIZE];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] encrypted = cipher.doFinal(value.getBytes());

            // 将初始向量 (IV) 和加密后的数据一起返回，以便解密
            byte[] combined = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String key, String encrypted) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), AES);
            Cipher cipher = Cipher.getInstance(AES_CTR_NOPADDING);

            byte[] combined = Base64.getDecoder().decode(encrypted);
            byte[] iv = new byte[IV_SIZE];
            System.arraycopy(combined, 0, iv, 0, iv.length);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            byte[] encrypted1 = new byte[combined.length - iv.length];
            System.arraycopy(combined, iv.length, encrypted1, 0, encrypted1.length);

            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] original = cipher.doFinal(encrypted1);

            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
}