import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCTR2 {

    private static final String AES_ALGORITHM = "AES";
    private static final String AES_MODE = "CTR";
    private static final String AES_PADDING = "NoPadding";
  
    private static final String key = "abcdefghijklmnop"; // 16 bytes key
    private static final String iv = "1234567890123456"; // 16 bytes IV

    public static void sendToParty1(String message) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM + "/" + AES_MODE + "/" + AES_PADDING);
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), AES_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
        String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
        System.out.println("Encrypted Message for Party 1: " + encodedMessage);
    }

    public static void sendToParty2(String message) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM + "/" + AES_MODE + "/" + AES_PADDING);
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), AES_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
        String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
        System.out.println("Encrypted Message for Party 2: " + encodedMessage);
    }

    public static void sendToParty3(String message) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM + "/" + AES_MODE + "/" + AES_PADDING);
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), AES_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
        String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
        System.out.println("Encrypted Message for Party 3: " + encodedMessage);
    }

    public static void main(String[] args) {
        try {
            sendToParty1("Hello Party 1!");
            sendToParty2("Hello Party 2!");
            sendToParty3("Hello Party 3!");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}