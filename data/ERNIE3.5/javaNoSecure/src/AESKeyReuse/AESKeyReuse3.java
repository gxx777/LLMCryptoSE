import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESKeyReuse3 {

    private static final String ALGORITHM = "AES";
    private static final byte[] KEY = "ThisIsASecretKey".getBytes(StandardCharsets.UTF_8); // 注意：这不是一个安全的密钥管理方式

    public static String encrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            // 参与方A发送消息给参与方B
            String messageAtoB = "Hello from A to B";
            String encryptedAtoB = encrypt(messageAtoB);
            System.out.println("A -> B: " + encryptedAtoB);

            // 参与方B接收消息并解密
            String decryptedAtoB = decrypt(encryptedAtoB);
            System.out.println("B decrypted from A: " + decryptedAtoB);

            // 参与方B发送消息给参与方C
            String messageBtoC = "Hello from B to C";
            String encryptedBtoC = encrypt(messageBtoC);
            System.out.println("B -> C: " + encryptedBtoC);

            // 参与方C接收消息并解密
            String decryptedBtoC = decrypt(encryptedBtoC);
            System.out.println("C decrypted from B: " + decryptedBtoC);

            // 参与方C发送消息给参与方A
            String messageCtoA = "Hello from C to A";
            String encryptedCtoA = encrypt(messageCtoA);
            System.out.println("C -> A: " + encryptedCtoA);

            // 参与方A接收消息并解密
            String decryptedCtoA = decrypt(encryptedCtoA);
            System.out.println("A decrypted from C: " + decryptedCtoA);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}