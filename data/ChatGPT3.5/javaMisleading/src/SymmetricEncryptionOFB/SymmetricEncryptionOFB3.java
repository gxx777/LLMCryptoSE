import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricEncryptionOFB3 {

    private SecretKey secretKey;
    private byte[] iv;

    public SymmetricEncryptionOFB3() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            secretKey = keyGenerator.generateKey();
            iv = new byte[16];
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public byte[] encrypt(String plainText) {
        try {
            Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
            return cipher.doFinal(plainText.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String decrypt(byte[] cipherText) {
        try {
            Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
            return new String(cipher.doFinal(cipherText));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

}