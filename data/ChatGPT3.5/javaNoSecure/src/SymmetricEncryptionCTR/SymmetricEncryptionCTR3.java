import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricEncryptionCTR3 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CTR/PKCS5Padding";

    private static final byte[] IV = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, (byte) 130, (byte) 140, (byte) 150, (byte) 160};

    private SecretKeySpec secretKeySpec;

    public SymmetricEncryptionCTR3(String key) {
        secretKeySpec = new SecretKeySpec(key.getBytes(), ALGORITHM);
    }

    public String encrypt(String input) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(IV));
            byte[] encryptedBytes = cipher.doFinal(input.getBytes());
            return new String(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public String decrypt(String input) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(IV));
            byte[] decryptedBytes = cipher.doFinal(input.getBytes());
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }
}