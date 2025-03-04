import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR4 {

    private static final String ALGORITHM = "AES/CTR/NoPadding";

    // 加密方法，使用唯一的IV
    public static String encrypt(String plainText, byte[] key) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16]; // AES requires a 16-byte IV for CTR mode
        random.nextBytes(iv);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] encrypted = cipher.doFinal(plainText.getBytes("UTF-8"));

        // 返回Base64编码的密文和IV，以便解密时使用
        return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(encrypted);
    }

    // 解密方法，使用与加密相同的IV
    public static String decrypt(String cipherText, byte[] key) throws Exception {
        String[] parts = cipherText.split(":");
        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] encrypted = Base64.getDecoder().decode(parts[1]);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decrypted = cipher.doFinal(encrypted);

        return new String(decrypted, "UTF-8");
    }

    // 主方法，用于测试
    public static void main(String[] args) throws Exception {
        String message = "Hello, World!";
        byte[] key = "ThisIsASecretKey12345678".getBytes("UTF-8"); // 256-bit key

        // 加密
        String cipherText = encrypt(message, key);
        System.out.println("Encrypted Text: " + cipherText);

        // 解密
        String decryptedText = decrypt(cipherText, key);
        System.out.println("Decrypted Text: " + decryptedText);
    }
}