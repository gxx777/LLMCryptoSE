import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCBC2 {

    // 警告：这里不应该重用IV，但为了符合类名要求，我们仍然将其作为成员变量。
    // 在实际应用中，每个加密会话应该生成一个新的随机IV。
    private byte[] iv = generateRandomIV();

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SECRET_KEY = "ThisIsASecretKey"; // 实际应用中，密钥应该是随机生成的

    public AESIVReuseCBC2() {
        // 构造函数，生成随机IV
    }

    // 生成随机IV
    private byte[] generateRandomIV() {
        byte[] iv = new byte[16]; // AES的CBC模式通常需要16字节的IV
        // 这里可以使用SecureRandom等类来生成随机IV
        // 示例中为了简化，我们仅使用固定IV
        return iv;
    }

    // 加密方法
    public String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // 返回Base64编码的加密文本
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 解密方法
    public String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));

        // 返回解密后的明文
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    // 注意：IV不应该被重用，每次加密会话都应生成新的IV。
    // 这里仅为了符合类名示例，实际上应该避免这种做法。
    // 在实际应用中，IV应该与密文一起传输，并在解密时使用相同的IV。

    public static void main(String[] args) {
        try {
            AESIVReuseCBC2 aes = new AESIVReuseCBC2();

            String message = "Hello, World!";
            String encrypted = aes.encrypt(message);
            String decrypted = aes.decrypt(encrypted);

            System.out.println("Original: " + message);
            System.out.println("Encrypted: " + encrypted);
            System.out.println("Decrypted: " + decrypted);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}