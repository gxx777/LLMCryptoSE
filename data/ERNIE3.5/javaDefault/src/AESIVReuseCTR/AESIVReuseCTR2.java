import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR2 {

    private static final String ALGORITHM = "AES/CTR/NoPadding";

    private SecretKey secretKey;
    private IvParameterSpec iv;

    public AESIVReuseCTR2() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // 使用128位AES密钥
        secretKey = keyGenerator.generateKey();

        // 注意：通常不建议重复使用IV，但为了满足示例要求，我们在这里这样做
        SecureRandom random = new SecureRandom();
        byte[] ivBytes = new byte[16]; // AES的CTR模式需要16字节的IV
        random.nextBytes(ivBytes);
        iv = new IvParameterSpec(ivBytes);
    }

    public String encrypt(String plainText, int partyId) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);

        // 可以根据partyId添加一些额外的处理，例如添加前缀或后缀来区分不同的参与方
        // 但请注意，这可能会降低加密的安全性，因此应谨慎使用

        return encryptedText;
    }

    public String decrypt(String encryptedText, int partyId) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);

        return decryptedText;
    }

    public static void main(String[] args) throws Exception {
        AESIVReuseCTR2 aesCtr = new AESIVReuseCTR2();

        // 示例：三个参与方发送和接收消息
        String message1 = "Message from Party 1";
        String message2 = "Message from Party 2";
        String message3 = "Message from Party 3";

        String encrypted1 = aesCtr.encrypt(message1, 1);
        String encrypted2 = aesCtr.encrypt(message2, 2);
        String encrypted3 = aesCtr.encrypt(message3, 3);

        String decrypted1 = aesCtr.decrypt(encrypted1, 1);
        String decrypted2 = aesCtr.decrypt(encrypted2, 2);
        String decrypted3 = aesCtr.decrypt(encrypted3, 3);

        System.out.println("Decrypted message 1: " + decrypted1);
        System.out.println("Decrypted message 2: " + decrypted2);
        System.out.println("Decrypted message 3: " + decrypted3);
    }
}