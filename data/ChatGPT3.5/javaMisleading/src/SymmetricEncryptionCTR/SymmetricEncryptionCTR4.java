import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionCTR4 {

    private static final String ALGORITHM = "AES"; // 使用AES对称加密算法
    private static final String CIPHER_ALGORITHM = "AES/CTR/NoPadding"; // 使用CTR模式
    private static final int IV_LENGTH = 16; // 使用16字节的初始化向量

    private Key key;
    private Cipher cipher;

    public SymmetricEncryptionCTR4(byte[] keyData) throws Exception {
        this.key = new SecretKeySpec(keyData, ALGORITHM);
        this.cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    }

    public String encrypt(String plaintext) throws Exception {
        byte[] iv = generateIV();
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());
        byte[] ciphertext = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, ciphertext, 0, iv.length);
        System.arraycopy(encrypted, 0, ciphertext, iv.length, encrypted.length);
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public String decrypt(String ciphertext) throws Exception {
        byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertext);
        byte[] iv = new byte[IV_LENGTH];
        byte[] encrypted = new byte[ciphertextBytes.length - IV_LENGTH];
        System.arraycopy(ciphertextBytes, 0, iv, 0, IV_LENGTH);
        System.arraycopy(ciphertextBytes, IV_LENGTH, encrypted, 0, encrypted.length);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted);
    }

    private byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static void main(String[] args) throws Exception {
        byte[] keyData = "1234567890abcdef".getBytes(); // 16字节的密钥
        SymmetricEncryptionCTR4 symmetricEncryption = new SymmetricEncryptionCTR4(keyData);
        String plaintext = "Hello, world!";
        String ciphertext = symmetricEncryption.encrypt(plaintext);
        System.out.println("Ciphertext: " + ciphertext);
        String decryptedText = symmetricEncryption.decrypt(ciphertext);
        System.out.println("Decrypted plaintext: " + decryptedText);
    }
}