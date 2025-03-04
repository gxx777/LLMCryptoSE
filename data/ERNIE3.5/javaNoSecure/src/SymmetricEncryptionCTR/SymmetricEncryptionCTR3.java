import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;

public class SymmetricEncryptionCTR3 {

    // 密钥
    private static final byte[] KEY = "ThisIsASecretKeyThisIsASecretKey".getBytes(StandardCharsets.UTF_8);

    // 初始化向量 (CTR模式需要它，但实际上不使用其内容)
    private static final byte[] IV = new byte[16];

    static {
        // 添加BouncyCastle作为安全提供者
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /**
     * 使用AES在CTR模式下加密字符串
     *
     * @param plaintext 要加密的明文
     * @return 加密后的密文，以Base64编码的字符串形式返回
     * @throws Exception 如果加密过程中出现错误
     */
    public static String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * 使用AES在CTR模式下解密字符串
     *
     * @param ciphertext 要解密的密文，以Base64编码的字符串形式提供
     * @return 解密后的明文
     * @throws Exception 如果解密过程中出现错误
     */
    public static String decrypt(String ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decoded = Base64.getDecoder().decode(ciphertext);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            String original = "Hello, World!";
            String encrypted = encrypt(original);
            String decrypted = decrypt(encrypted);

            System.out.println("Original: " + original);
            System.out.println("Encrypted: " + encrypted);
            System.out.println("Decrypted: " + decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}