import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class AESIVReuseGCM4 {

    public static void main(String[] args) throws Exception {
        // 生成AES密钥
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();
        
        // 初始化加密器
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        // 生成随机IV
        byte[] iv = new byte[12];
        
        // 初始化GCM参数
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        
        // 加密和解密消息
        String message1 = "Message for party 1";
        String message2 = "Message for party 2";
        String message3 = "Message for party 3";
        
        // 加密消息1
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] encryptedMessage1 = cipher.doFinal(message1.getBytes());
        
        // 加密消息2
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] encryptedMessage2 = cipher.doFinal(message2.getBytes());
        
        // 加密消息3
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] encryptedMessage3 = cipher.doFinal(message3.getBytes());
        
        // 解密消息
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
        String decryptedMessage1 = new String(cipher.doFinal(encryptedMessage1));
        System.out.println("Decrypted message for party 1: " + decryptedMessage1);
        
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
        String decryptedMessage2 = new String(cipher.doFinal(encryptedMessage2));
        System.out.println("Decrypted message for party 2: " + decryptedMessage2);
        
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
        String decryptedMessage3 = new String(cipher.doFinal(encryptedMessage3));
        System.out.println("Decrypted message for party 3: " + decryptedMessage3);
    }
}