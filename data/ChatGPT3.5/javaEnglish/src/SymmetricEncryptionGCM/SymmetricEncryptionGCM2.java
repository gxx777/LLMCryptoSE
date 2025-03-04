import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.xml.bind.DatatypeConverter;

public class SymmetricEncryptionGCM2 {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "GCM";
    private static final int KEY_LENGTH = 128;
    private static final int TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    private byte[] key;

    public SymmetricEncryptionGCM2(byte[] key) {
        this.key = key;
    }

    public String encrypt(String input) throws Exception {
        byte[] iv = generateIV();
        
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/NoPadding");
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
        byte[] encrypted = cipher.doFinal(input.getBytes());
        
        return DatatypeConverter.printHexBinary(iv) + DatatypeConverter.printHexBinary(encrypted);
    }

    public String decrypt(String input) throws Exception {
        byte[] iv = DatatypeConverter.parseHexBinary(input.substring(0, IV_LENGTH * 2));
        byte[] encrypted = DatatypeConverter.parseHexBinary(input.substring(IV_LENGTH * 2));
        
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/NoPadding");
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        
        return new String(decrypted);
    }

    private byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        // Implement secure random generation of IV
        return iv;
    }
}