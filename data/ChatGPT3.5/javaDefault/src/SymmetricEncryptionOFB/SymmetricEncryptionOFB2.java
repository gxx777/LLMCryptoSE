import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricEncryptionOFB2 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/OFB/NoPadding";

    private SecretKeySpec key;
    private IvParameterSpec iv;

    public SymmetricEncryptionOFB2(byte[] key, byte[] iv) {
        this.key = new SecretKeySpec(key, ALGORITHM);
        this.iv = new IvParameterSpec(iv);
    }

    public byte[] encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(plaintext.getBytes());
    }

    public String decrypt(byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            byte[] key = "0123456789abcdef".getBytes();
            byte[] iv = "abcdef0123456789".getBytes();

            SymmetricEncryptionOFB2 symmetricEncryption = new SymmetricEncryptionOFB2(key, iv);

            String plaintext = "This is a secret message";
            byte[] encrypted = symmetricEncryption.encrypt(plaintext);
            System.out.println("Encrypted: " + new String(encrypted));

            String decrypted = symmetricEncryption.decrypt(encrypted);
            System.out.println("Decrypted: " + decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}