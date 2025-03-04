import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SymmetricEncryptionCFB2 {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CFB/PKCS5Padding";

    private SecretKeySpec key;
    private IvParameterSpec iv;

    public SymmetricEncryptionCFB2(byte[] key, byte[] iv) {
        this.key = new SecretKeySpec(key, ALGORITHM);
        this.iv = new IvParameterSpec(iv);
    }

    public String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            byte[] key = "1234567890123456".getBytes();
            byte[] iv = "abcdef0123456789".getBytes();

            SymmetricEncryptionCFB2 symmetricEncryption = new SymmetricEncryptionCFB2(key, iv);

            String plaintext = "Hello, World!";
            String ciphertext = symmetricEncryption.encrypt(plaintext);
            System.out.println("Encrypted text: " + ciphertext);

            String decryptedText = symmetricEncryption.decrypt(ciphertext);
            System.out.println("Decrypted text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}