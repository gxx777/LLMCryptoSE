import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Arrays;

public class AESIVReuseGCM2 {

    public static void main(String[] args) throws Exception {
        // 生成AES密钥
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();

        // 生成随机的IV
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // 初始化加密器
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        // 模拟三个不同参与方发送消息
        String[] participants = {"Alice", "Bob", "Charlie"};
        for (String participant : participants) {
            // 加密消息
            String message = "Hello, " + participant + "!";
            byte[] ciphertext = cipher.doFinal(message.getBytes());

            // 解密消息
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            byte[] decrypted = cipher.doFinal(ciphertext);

            // 打印结果
            System.out.println("Original message: " + message);
            System.out.println("Decrypted message: " + new String(decrypted));
            System.out.println();
        }
    }
}