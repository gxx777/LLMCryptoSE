import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;

public class SymmetricEncryptionCTR4 {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "CTR";
    private static final int KEY_SIZE = 128;

    private Key key;
    private IvParameterSpec iv;

    public SymmetricEncryptionCTR4(byte[] keyBytes) {
        key = new SecretKeySpec(keyBytes, ALGORITHM);
        iv = generateIV();
    }

    private IvParameterSpec generateIV() {
        byte[] ivBytes = new byte[KEY_SIZE / 8];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivBytes);
        return new IvParameterSpec(ivBytes);
    }

    public byte[] encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(plaintext.getBytes());
    }

    public String decrypt(byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plaintextBytes = cipher.doFinal(ciphertext);
        return new String(plaintextBytes);
    }

    public static void main(String[] args) {
        try {
            byte[] keyBytes = new byte[KEY_SIZE / 8];
            SecureRandom random = new SecureRandom();
            random.nextBytes(keyBytes);

            SymmetricEncryptionCTR4 encryption = new SymmetricEncryptionCTR4(keyBytes);

            String plaintext = "Hello, World!";
            byte[] ciphertext = encryption.encrypt(plaintext);
            System.out.println("Encrypted: " + new String(ciphertext));

            String decryptedText = encryption.decrypt(ciphertext);
            System.out.println("Decrypted: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}