import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESKeyReuse2 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

    // 生成AES密钥和初始化向量(IV)
    public static String generateKeyAndIv() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // AES-128
        SecretKey secretKey = keyGenerator.generateKey();
        byte[] keyBytes = secretKey.getEncoded();
        byte[] ivBytes = new byte[16]; // AES/CBC/PKCS5Padding 需要 16 字节的 IV
        new SecureRandom().nextBytes(ivBytes);

        // 返回Base64编码的密钥和IV字符串
        return Base64.getEncoder().encodeToString(keyBytes) + ":" + Base64.getEncoder().encodeToString(ivBytes);
    }

    // 使用给定的密钥和IV加密消息
    public static String encrypt(String message, String keyAndIv) throws Exception {
        String[] parts = keyAndIv.split(":");
        byte[] keyBytes = Base64.getDecoder().decode(parts[0]);
        byte[] ivBytes = Base64.getDecoder().decode(parts[1]);

        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes()));
    }

    // 使用给定的密钥和IV解密消息
    public static String decrypt(String encryptedMessage, String keyAndIv) throws Exception {
        String[] parts = keyAndIv.split(":");
        byte[] keyBytes = Base64.getDecoder().decode(parts[0]);
        byte[] ivBytes = Base64.getDecoder().decode(parts[1]);

        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedMessage)));
    }

    public static void main(String[] args) {
        try {
            // 生成密钥和IV
            String keyAndIv = generateKeyAndIv();

            // 模拟三个参与方发送和接收消息
            String messagePartyA = "Hello from Party A!";
            String encryptedMessagePartyA = encrypt(messagePartyA, keyAndIv);
            String decryptedMessagePartyA = decrypt(encryptedMessagePartyA, keyAndIv);

            String messagePartyB = "Hello from Party B!";
            String encryptedMessagePartyB = encrypt(messagePartyB, keyAndIv);
            String decryptedMessagePartyB = decrypt(encryptedMessagePartyB, keyAndIv);

            String messagePartyC = "Hello from Party C!";
            String encryptedMessagePartyC = encrypt(messagePartyC, keyAndIv);
            String decryptedMessagePartyC = decrypt(encryptedMessagePartyC, keyAndIv);

            // 打印结果
            System.out.println("Party A: Original: " + messagePartyA + ", Encrypted: " + encryptedMessagePartyA + ", Decrypted: " + decryptedMessagePartyA);
            System.out.println("Party B: Original: " + messagePartyB + ", Encrypted: " + encryptedMessagePartyB + ", Decrypted: " + decryptedMessagePartyB);
            System.out.println("Party C: Original: " + messagePartyC + ", Encrypted: " + encryptedMessagePartyC + ", Decrypted: " + decryptedMessagePartyC);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}