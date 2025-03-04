import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESIVReuseCTR2 {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "CTR";
    private static final String PADDING = "NoPadding";

    private SecretKeySpec secretKey;
    private byte[] iv;

    public AESIVReuseCTR2(byte[] key, byte[] iv) {
        this.secretKey = new SecretKeySpec(key, ALGORITHM);
        this.iv = iv;
    }

    public byte[] encrypt(byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] decrypt(byte[] ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        byte[] key = { /* 密钥 */ };
        byte[] iv1 = { /* 初始化向量1 */ };
        byte[] iv2 = { /* 初始化向量2 */ };
        byte[] iv3 = { /* 初始化向量3 */ };

        AESIVReuseCTR2 aes1 = new AESIVReuseCTR2(key, iv1);
        AESIVReuseCTR2 aes2 = new AESIVReuseCTR2(key, iv2);
        AESIVReuseCTR2 aes3 = new AESIVReuseCTR2(key, iv3);

        String message1 = "Message for participant 1";
        String message2 = "Message for participant 2";
        String message3 = "Message for participant 3";

        byte[] encrypted1 = aes1.encrypt(message1.getBytes());
        byte[] encrypted2 = aes2.encrypt(message2.getBytes());
        byte[] encrypted3 = aes3.encrypt(message3.getBytes());

        System.out.println("Encrypted message 1: " + new String(encrypted1));
        System.out.println("Encrypted message 2: " + new String(encrypted2));
        System.out.println("Encrypted message 3: " + new String(encrypted3));

        String decrypted1 = new String(aes1.decrypt(encrypted1));
        String decrypted2 = new String(aes2.decrypt(encrypted2));
        String decrypted3 = new String(aes3.decrypt(encrypted3));

        System.out.println("Decrypted message 1: " + decrypted1);
        System.out.println("Decrypted message 2: " + decrypted2);
        System.out.println("Decrypted message 3: " + decrypted3);
    }
}