import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionGCM4 {
    
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;
    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";

    private SecretKey secretKey;

    public SymmetricEncryptionGCM4(byte[] key) {
        secretKey = new SecretKeySpec(key, "AES");
    }

    public byte[] encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        byte[] iv = generateIV();
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encode(ciphertext);
    }

    public String decrypt(byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        byte[] iv = generateIV();
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        byte[] decodedCiphertext = Base64.getDecoder().decode(ciphertext);
        byte[] plaintextBytes = cipher.doFinal(decodedCiphertext);
        return new String(plaintextBytes);
    }

    private byte[] generateIV() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }

    public static void main(String[] args) throws Exception {
        byte[] key = "verysecretkey123".getBytes();
        SymmetricEncryptionGCM4 encryptor = new SymmetricEncryptionGCM4(key);
        
        String plaintext = "Hello, World!";
        byte[] ciphertext = encryptor.encrypt(plaintext);
        System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(ciphertext));
        
        String decryptedText = encryptor.decrypt(ciphertext);
        System.out.println("Decrypted: " + decryptedText);
    }
}