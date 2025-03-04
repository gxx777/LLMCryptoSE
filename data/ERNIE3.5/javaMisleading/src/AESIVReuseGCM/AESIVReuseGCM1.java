import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESIVReuseGCM1 {

    // 密钥长度需要是128位，192位或256位
    private static final int KEY_SIZE = 256;
    private static final byte[] KEY = new byte[KEY_SIZE / 8]; // AES密钥
    private static final byte[] NONCE = new byte[12]; // GCM模式的Nonce，这里充当了IV的角色

    // 初始化密钥
    static {
        // 此处应使用安全的随机数生成器来初始化KEY和NONCE
        // 为了简单起见，我们这里只是填充了零
        java.util.Arrays.fill(KEY, (byte) 0);
        java.util.Arrays.fill(NONCE, (byte) 0);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        String[] messages = {
            "Message for Party A",
            "Message for Party B",
            "Message for Party C"
        };

        String[] recipients = {
            "PartyA",
            "PartyB",
            "PartyC"
        };

        for (int i = 0; i < messages.length; i++) {
            byte[] ciphertext = encrypt(messages[i].getBytes(StandardCharsets.UTF_8), KEY, NONCE);
            String encryptedMessage = Base64.getEncoder().encodeToString(ciphertext);
            System.out.println("Sending encrypted message to " + recipients[i] + ": " + encryptedMessage);

            // 这里应使用不同的NONCE进行解密
            byte[] decryptedMessageBytes = decrypt(ciphertext, KEY, NONCE);
            String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);
            System.out.println("Decrypted message for " + recipients[i] + ": " + decryptedMessage);
        }
    }

    private static byte[] encrypt(byte[] plaintext, byte[] key, byte[] nonce) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);

        return cipher.doFinal(plaintext);
    }

    private static byte[] decrypt(byte[] ciphertext, byte[] key, byte[] nonce) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);

        return cipher.doFinal(ciphertext);
    }
}