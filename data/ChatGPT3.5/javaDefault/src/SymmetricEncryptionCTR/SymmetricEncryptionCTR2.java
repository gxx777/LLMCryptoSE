import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionCTR2 {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "CTR";
    private static final String PADDING = "NoPadding";
    private static final int KEY_SIZE = 16; // 128-bit key

    private Key key;
    private IvParameterSpec ivParameterSpec;

    public SymmetricEncryptionCTR2(String keyString) {
        byte[] keyBytes = keyString.getBytes();
        this.key = new SecretKeySpec(keyBytes, ALGORITHM);
        this.ivParameterSpec = generateIV();
    }

    private IvParameterSpec generateIV() {
        byte[] iv = new byte[KEY_SIZE];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public String encrypt(String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String decrypt(String ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
            cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        String key = "abcdefghijklmnop"; // 16 bytes key
        SymmetricEncryptionCTR2 symmetricEncryptionCTR2 = new SymmetricEncryptionCTR2(key);

        String plaintext = "Hello, World!";
        System.out.println("Original: " + plaintext);

        String encrypted = symmetricEncryptionCTR2.encrypt(plaintext);
        System.out.println("Encrypted: " + encrypted);

        String decrypted = symmetricEncryptionCTR2.decrypt(encrypted);
        System.out.println("Decrypted: " + decrypted);
    }
}