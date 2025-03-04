import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricEncryptionCFB1 {

    private static final String transformation = "AES/CFB/NoPadding";
    private static final String secretKey = "your_secret_key_here";
    private static final String iv = "your_random_iv_here";

    public static byte[] encrypt(String plaintext) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
        
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);
        
        return cipher.doFinal(plaintext.getBytes());
    }

    public static String decrypt(byte[] ciphertext) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
        
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);
        
        return new String(cipher.doFinal(ciphertext));
    }

    public static void main(String[] args) throws Exception {
        String plaintext = "Hello, world!";
        
        byte[] encrypted = encrypt(plaintext);
        System.out.println("Encrypted: " + new String(encrypted));
        
        String decrypted = decrypt(encrypted);
        System.out.println("Decrypted: " + decrypted);
    }
}