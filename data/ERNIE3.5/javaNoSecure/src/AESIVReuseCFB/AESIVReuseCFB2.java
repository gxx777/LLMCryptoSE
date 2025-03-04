import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCFB2 {

    private static final String ALGORITHM = "AES/CFB/NoPadding";

    // 假设我们有三个参与方A, B, C，每个参与方都有一个固定的密钥，但IV会每次改变
    private static final byte[] KEY_A = "KeyA".getBytes(StandardCharsets.UTF_8);
    private static final byte[] KEY_B = "KeyB".getBytes(StandardCharsets.UTF_8);
    private static final byte[] KEY_C = "KeyC".getBytes(StandardCharsets.UTF_8);

    // 初始化向量(IV)，为每个参与方分别维护一个
    private static final byte[] IV_A = "IVA".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV_B = "IVB".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV_C = "IVC".getBytes(StandardCharsets.UTF_8);

    // 加密方法
    public static String encrypt(String plaintext, byte[] key, byte[] iv) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);

        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // 解密方法
    public static String decrypt(String ciphertext, byte[] key, byte[] iv) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);

        byte[] original = cipher.doFinal(Base64.getDecoder().decode(ciphertext));

        return new String(original, StandardCharsets.UTF_8);
    }

    // 示例：发送消息给参与方A
    public static void sendMessageToA(String message) throws Exception {
        String ciphertext = encrypt(message, KEY_A, IV_A);
        System.out.println("Sent encrypted message to A: " + ciphertext);

        // 接收方A解密
        String decryptedMessage = decrypt(ciphertext, KEY_A, IV_A);
        System.out.println("Received decrypted message from A: " + decryptedMessage);
    }

    // 示例：发送消息给参与方B
    public static void sendMessageToB(String message) throws Exception {
        String ciphertext = encrypt(message, KEY_B, IV_B);
        System.out.println("Sent encrypted message to B: " + ciphertext);

        // 接收方B解密
        String decryptedMessage = decrypt(ciphertext, KEY_B, IV_B);
        System.out.println("Received decrypted message from B: " + decryptedMessage);
    }

    // 示例：发送消息给参与方C
    public static void sendMessageToC(String message) throws Exception {
        String ciphertext = encrypt(message, KEY_C, IV_C);
        System.out.println("Sent encrypted message to C: " + ciphertext);

        // 接收方C解密
        String decryptedMessage = decrypt(ciphertext, KEY_C, IV_C);
        System.out.println("Received decrypted message from C: " + decryptedMessage);
    }
}