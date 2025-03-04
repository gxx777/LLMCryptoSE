import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM3 {

    public static void main(String[] args) throws Exception {
        // 生成AES密钥
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();

        // 生成随机IV
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);

        // 加密并发送消息给三个不同的参与方
        sendMessage(secretKey, gcmParameterSpec, "message to participant 1", "Participant 1");
        sendMessage(secretKey, gcmParameterSpec, "message to participant 2", "Participant 2");
        sendMessage(secretKey, gcmParameterSpec, "message to participant 3", "Participant 3");
    }

    public static void sendMessage(SecretKey secretKey, GCMParameterSpec gcmParameterSpec, String message, String participantName) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());

        // 模拟发送加密消息给参与方
        System.out.println("Sending encrypted message to " + participantName + ": " + Base64.getEncoder().encodeToString(encryptedMessage));
    }
}