import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

public class SymmetricEncryptionCTR2 {

    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String CIPHER_MODE = "AES/CTR/NoPadding";
    private static final int BLOCK_SIZE = 16;

    private Key key;
    private IvParameterSpec iv;

    public SymmetricEncryptionCTR2(byte[] keyBytes, byte[] ivBytes) {
        key = new SecretKeySpec(keyBytes, ENCRYPTION_ALGORITHM);
        iv = new IvParameterSpec(ivBytes);
    }

    public byte[] encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return encryptedBytes;
    }

    public String decrypt(byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_MODE);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        byte[] key = "1234567890123456".getBytes();
        byte[] iv = "abcdefghijklmnop".getBytes();
        SymmetricEncryptionCTR2 encryption = new SymmetricEncryptionCTR2(key, iv);

        String plaintext = "Hello, World!";
        try {
            byte[] ciphertext = encryption.encrypt(plaintext);
            System.out.println("Encrypted text: " + new String(ciphertext));

            String decryptedText = encryption.decrypt(ciphertext);
            System.out.println("Decrypted text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}