import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionGCM4 {
    
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    private SecretKeySpec secretKey;

    public SymmetricEncryptionGCM4(byte[] key) {
        this.secretKey = new SecretKeySpec(key, "AES");
    }

    public byte[] encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
        return result;
    }

    public String decrypt(byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[IV_LENGTH];
        byte[] encryptedText = new byte[ciphertext.length - IV_LENGTH];
        System.arraycopy(ciphertext, 0, iv, 0, iv.length);
        System.arraycopy(ciphertext, iv.length, encryptedText, 0, encryptedText.length);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        byte[] plaintextBytes = cipher.doFinal(encryptedText);
        return new String(plaintextBytes);
    }

    public static void main(String[] args) throws Exception {
        byte[] key = "secretkey1234567".getBytes();
        SymmetricEncryptionGCM4 encryptor = new SymmetricEncryptionGCM4(key);
        String plaintext = "Hello, World!";
        byte[] ciphertext = encryptor.encrypt(plaintext);
        String decryptedText = encryptor.decrypt(ciphertext);
        System.out.println("Original: " + plaintext);
        System.out.println("Decrypted: " + decryptedText);
    }
}