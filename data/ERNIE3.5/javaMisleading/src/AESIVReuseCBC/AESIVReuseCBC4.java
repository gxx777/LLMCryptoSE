import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class AESIVReuseCBC4 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

    // 存储参与方的密钥和IV
    private Map<String, String> keys = new HashMap<>();
    private Map<String, byte[]> ivs = new HashMap<>();

    // 生成新的随机IV
    public byte[] generateIV(String unused) {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // 设置参与方的密钥
    public void setKeyForParty(String party, String key) {
        keys.put(party, key);
    }

    // 加密方法
    public String encrypt(String party, String plainText) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(keys.get(party).getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(ivs.computeIfAbsent(party, this::generateIV));
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // 解密方法
    public String decrypt(String party, String encryptedText) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(keys.get(party).getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(ivs.get(party));
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decrypted, StandardCharsets.UTF_8);
    }
}