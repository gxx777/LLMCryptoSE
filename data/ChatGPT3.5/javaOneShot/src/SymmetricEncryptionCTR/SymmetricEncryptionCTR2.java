import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SymmetricEncryptionCTR2 {

    private static final String ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CTR/NoPadding";
    private static final int IV_LENGTH = 16;

    private Key key;

    public SymmetricEncryptionCTR2(String keyString) {
        this.key = new SecretKeySpec(keyString.getBytes(StandardCharsets.UTF_8), ALGORITHM);
    }

    public byte[] encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        byte[] iv = generateIV();
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        return concatenateArrays(iv, ciphertext);
    }

    public String decrypt(byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        byte[] iv = extractIV(ciphertext);
        byte[] encryptedData = extractEncryptedData(ciphertext);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] plaintextBytes = cipher.doFinal(encryptedData);

        return new String(plaintextBytes, StandardCharsets.UTF_8);
    }

    private byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private byte[] concatenateArrays(byte[] arr1, byte[] arr2) {
        byte[] concatenated = new byte[arr1.length + arr2.length];
        System.arraycopy(arr1, 0, concatenated, 0, arr1.length);
        System.arraycopy(arr2, 0, concatenated, arr1.length, arr2.length);
        return concatenated;
    }

    private byte[] extractIV(byte[] ciphertext) {
        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(ciphertext, 0, iv, 0, IV_LENGTH);
        return iv;
    }

    private byte[] extractEncryptedData(byte[] ciphertext) {
        byte[] encryptedData = new byte[ciphertext.length - IV_LENGTH];
        System.arraycopy(ciphertext, IV_LENGTH, encryptedData, 0, encryptedData.length);
        return encryptedData;
    }

    public static void main(String[] args) {
        try {
            String keyString = "randomlygeneratedkey";
            SymmetricEncryptionCTR2 encryption = new SymmetricEncryptionCTR2(keyString);

            String originalText = "Hello, world!";
            byte[] ciphertext = encryption.encrypt(originalText);
            System.out.println("Encrypted: " + new String(ciphertext, StandardCharsets.UTF_8));

            String decryptedText = encryption.decrypt(ciphertext);
            System.out.println("Decrypted: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}