import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESIVReuseCTR3 {
    
    private static final String ALGORITHM = "AES";
    private static final String MODE = "CTR";
    
    private SecretKeySpec secretKey;
    
    public AESIVReuseCTR3(byte[] key) {
        secretKey = new SecretKeySpec(key, ALGORITHM);
    }
    
    public byte[] encrypt(byte[] input, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(input);
    }
    
    public byte[] decrypt(byte[] input, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(input);
    }
    
    public static void main(String[] args) {
        byte[] key = "1234567890123456".getBytes();
        byte[] iv1 = "abcdefgh12345678".getBytes();
        byte[] iv2 = "ijklmnop12345678".getBytes();
        byte[] iv3 = "qrstuvwx12345678".getBytes();
        
        AESIVReuseCTR3 aes = new AESIVReuseCTR3(key);
        
        try {
            // Encrypt and decrypt for participant 1
            String plaintext1 = "Hello Participant 1";
            byte[] ciphertext1 = aes.encrypt(plaintext1.getBytes(), iv1);
            byte[] decrypted1 = aes.decrypt(ciphertext1, iv1);
            System.out.println("Participant 1 - Decrypted Message: " + new String(decrypted1));
            
            // Encrypt and decrypt for participant 2
            String plaintext2 = "Hello Participant 2";
            byte[] ciphertext2 = aes.encrypt(plaintext2.getBytes(), iv2);
            byte[] decrypted2 = aes.decrypt(ciphertext2, iv2);
            System.out.println("Participant 2 - Decrypted Message: " + new String(decrypted2));
            
            // Encrypt and decrypt for participant 3
            String plaintext3 = "Hello Participant 3";
            byte[] ciphertext3 = aes.encrypt(plaintext3.getBytes(), iv3);
            byte[] decrypted3 = aes.decrypt(ciphertext3, iv3);
            System.out.println("Participant 3 - Decrypted Message: " + new String(decrypted3));
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}