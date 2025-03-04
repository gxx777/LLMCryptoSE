import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionCTR3 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CTR/NoPadding";
    private static final int IV_LENGTH = 16;

    private byte[] keyBytes;

    public SymmetricEncryptionCTR3(byte[] key) {
        this.keyBytes = key;
    }

    public String encrypt(String input) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            Key key = new SecretKeySpec(keyBytes, ALGORITHM);
            byte[] iv = generateIV();
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

            byte[] encryptedBytes = cipher.doFinal(input.getBytes());
            byte[] result = new byte[iv.length + encryptedBytes.length];

            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(encryptedBytes, 0, result, iv.length, encryptedBytes.length);

            return Base64.getEncoder().encodeToString(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public String decrypt(String input) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            Key key = new SecretKeySpec(keyBytes, ALGORITHM);

            byte[] decodedBytes = Base64.getDecoder().decode(input);
            byte[] iv = new byte[IV_LENGTH];
            byte[] encryptedBytes = new byte[decodedBytes.length - IV_LENGTH];

            System.arraycopy(decodedBytes, 0, iv, 0, IV_LENGTH);
            System.arraycopy(decodedBytes, IV_LENGTH, encryptedBytes, 0, encryptedBytes.length);

            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

            return new String(cipher.doFinal(encryptedBytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}