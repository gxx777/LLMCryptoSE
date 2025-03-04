import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AESIVReuseCFB2 {
  
    private static final String ALGORITHM = "AES";
    private static final String MODE = "CFB";
    
    private SecretKey secretKey;
    
    public AESIVReuseCFB2() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(128);
            secretKey = keyGen.generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public byte[] encrypt(byte[] message, IvParameterSpec iv) {
        return crypt(Cipher.ENCRYPT_MODE, message, iv);
    }
    
    public byte[] decrypt(byte[] cipherText, IvParameterSpec iv) {
        return crypt(Cipher.DECRYPT_MODE, cipherText, iv);
    }
    
    private byte[] crypt(int mode, byte[] input, IvParameterSpec iv) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/NoPadding");

            cipher.init(mode, secretKey, iv);
            return cipher.doFinal(input);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}