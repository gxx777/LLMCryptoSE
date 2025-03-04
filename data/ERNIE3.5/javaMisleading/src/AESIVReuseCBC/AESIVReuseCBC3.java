import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;

public class AESIVReuseCBC3 {

    // 使用固定的IV（这是不安全的，仅用于示例）
    private static final byte[] IV = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    // 使用固定的密钥（这也是不安全的，密钥应该动态生成并妥善保管）
    private static final byte[] KEY = "MySuperSecretKey".getBytes(StandardCharsets.UTF_8);

    // 初始化加密器
    private Cipher initCipher(int mode) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);
        cipher.init(mode, secretKeySpec, ivParameterSpec);
        return cipher;
    }

    // 加密方法
    public String encrypt(String plainText) throws Exception {
        Cipher cipher = initCipher(Cipher.ENCRYPT_MODE);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // 解密方法
    public String decrypt(String cipherText) throws Exception {
        Cipher cipher = initCipher(Cipher.DECRYPT_MODE);
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        byte[] decrypted = cipher.doFinal(bytes);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    // 测试方法
    public static void main(String[] args) throws Exception {
        AESIVReuseCBC3 aes = new AESIVReuseCBC3();

        // 参与方A发送的消息
        String messageA = "Message from Party A";
        String encryptedA = aes.encrypt(messageA);
        System.out.println("Encrypted A: " + encryptedA);

        // 参与方B发送消息
        String messageB = "Message from Party B";
        String encryptedB = aes.encrypt(messageB);
        System.out.println("Encrypted B: " + encryptedB);

        // 参与方C发送消息
        String messageC = "Message from Party C";
        String encryptedC = aes.encrypt(messageC);
        System.out.println("Encrypted C: " + encryptedC);

        // 接收方解密消息
        System.out.println("Decrypted A: " + aes.decrypt(encryptedA));
        System.out.println("Decrypted B: " + aes.decrypt(encryptedB));
        System.out.println("Decrypted C: " + aes.decrypt(encryptedC));
    }
}