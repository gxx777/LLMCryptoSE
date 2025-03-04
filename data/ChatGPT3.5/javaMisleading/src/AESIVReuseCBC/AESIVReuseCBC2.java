import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCBC2 {

    private static final String key = "0123456789abcdef"; // 16字节的密钥，此处使用16进制表示
    private static final String transformation = "AES/CBC/PKCS5Padding"; // 使用AES的CBC模式和PKCS5Padding填充
    private static final String ALGORITHM = "AES";

    public static void main(String[] args) {
        try {
            // 生成随机的16字节初始向量
            byte[] iv = new byte[16];
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            // 生成密钥
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), ALGORITHM);

            // 加密并解密消息
            String message = "Hello, World!";
            byte[] encryptedMessage = encrypt(message, secretKeySpec, ivParameterSpec);
            String decryptedMessage = decrypt(encryptedMessage, secretKeySpec, ivParameterSpec);

            System.out.println("Original Message: " + message);
            System.out.println("Encrypted Message: " + Base64.getEncoder().encodeToString(encryptedMessage));
            System.out.println("Decrypted Message: " + decryptedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] encrypt(String message, SecretKeySpec secretKeySpec, IvParameterSpec ivParameterSpec) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(message.getBytes());
    }

    public static String decrypt(byte[] encryptedMessage, SecretKeySpec secretKeySpec, IvParameterSpec ivParameterSpec) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decryptedMessage = cipher.doFinal(encryptedMessage);
        return new String(decryptedMessage);
    }
}