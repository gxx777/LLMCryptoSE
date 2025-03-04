import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCBC3 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final byte[] KEY = "ThisIsASecretKeyThisIsASecretKey".getBytes(StandardCharsets.UTF_8);
    // 注意：实际应用中不应该重复使用IV，这里仅为示例
    private static final byte[] INIT_VECTOR = "MyInitVector".getBytes(StandardCharsets.UTF_8);

    public static String encrypt(String valueToEnc) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR);
        SecretKeySpec skeySpec = new SecretKeySpec(KEY, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        byte[] encrypted = cipher.doFinal(valueToEnc.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encrypted) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR);
        SecretKeySpec skeySpec = new SecretKeySpec(KEY, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));

        return new String(original, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            // 参与方1发送的消息
            String message1 = "Message from Party 1";
            String encryptedMessage1 = encrypt(message1);
            System.out.println("Encrypted Message 1: " + encryptedMessage1);
            String decryptedMessage1 = decrypt(encryptedMessage1);
            System.out.println("Decrypted Message 1: " + decryptedMessage1);

            // 参与方2发送消息
            String message2 = "Message from Party 2";
            String encryptedMessage2 = encrypt(message2);
            System.out.println("Encrypted Message 2: " + encryptedMessage2);
            String decryptedMessage2 = decrypt(encryptedMessage2);
            System.out.println("Decrypted Message 2: " + decryptedMessage2);

            // 参与方3发送消息
            String message3 = "Message from Party 3";
            String encryptedMessage3 = encrypt(message3);
            System.out.println("Encrypted Message 3: " + encryptedMessage3);
            String decryptedMessage3 = decrypt(encryptedMessage3);
            System.out.println("Decrypted Message 3: " + decryptedMessage3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}