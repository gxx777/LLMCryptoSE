import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseOFB4 {
    private static final String key = "AESEncryptionKey";
    private static final String initVector = "RandomInitVector";

    public static String encrypt(String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String encrypted) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);

            byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
            return new String(original);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        String message1 = "密文1";
        String message2 = "密文2";
        String message3 = "密文3";

        String encrypted1 = encrypt(message1);
        String encrypted2 = encrypt(message2);
        String encrypted3 = encrypt(message3);

        System.out.println("加密后的第一条消息: " + encrypted1);
        System.out.println("加密后的第二条消息: " + encrypted2);
        System.out.println("加密后的第三条消息: " + encrypted3);

        String decrypted1 = decrypt(encrypted1);
        String decrypted2 = decrypt(encrypted2);
        String decrypted3 = decrypt(encrypted3);

        System.out.println("解密后的第一条消息: " + decrypted1);
        System.out.println("解密后的第二条消息: " + decrypted2);
        System.out.println("解密后的第三条消息: " + decrypted3);
    }
}