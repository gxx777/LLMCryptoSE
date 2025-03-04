import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESIVReuseOFB4 {

    public static void main(String[] args) throws Exception {
        // 生成密钥
        byte[] key = "1234567890123456".getBytes();  // 16字节的AES密钥

        // 初始化参与方A
        String msgA = "Hello from Participant A!";
        byte[] ivA = "1234567890123456".getBytes();  // 初始向量
        byte[] encryptedMsgA = encrypt(msgA, key, ivA);
        System.out.println("Encrypted message from Participant A: " + new String(encryptedMsgA));

        // 初始化参与方B
        String msgB = "Hi from Participant B!";
        byte[] ivB = "1234567890123456".getBytes();  // 初始向量
        byte[] encryptedMsgB = encrypt(msgB, key, ivB);
        System.out.println("Encrypted message from Participant B: " + new String(encryptedMsgB));

        // 初始化参与方C
        String msgC = "Hey from Participant C!";
        byte[] ivC = "1234567890123456".getBytes();  // 初始向量
        byte[] encryptedMsgC = encrypt(msgC, key, ivC);
        System.out.println("Encrypted message from Participant C: " + new String(encryptedMsgC));
    }

    public static byte[] encrypt(String message, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(message.getBytes());
    }
}