import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR4 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CTR/NoPadding";
    private static final int IV_LENGTH = 16;
    private static final int AES_KEY_SIZE = 256;

    private byte[] iv;
    private byte[] key;

    public AESIVReuseCTR4() {
        this.iv = generateRandomIV();
        this.key = generateRandomKey();
    }

    private byte[] generateRandomIV() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private byte[] generateRandomKey() {
        byte[] key = new byte[AES_KEY_SIZE / 8];
        new SecureRandom().nextBytes(key);
        return key;
    }

    public String encrypt(String plaintext, byte[] iv, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String ciphertext, byte[] iv, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        AESIVReuseCTR4 aes = new AESIVReuseCTR4();

        String plaintext1 = "Hello, Participant 1!";
        String plaintext2 = "Hello, Participant 2!";
        String plaintext3 = "Hello, Participant 3!";

        byte[] iv1 = aes.generateRandomIV();
        byte[] iv2 = aes.generateRandomIV();
        byte[] iv3 = aes.generateRandomIV();

        byte[] key1 = aes.generateRandomKey();
        byte[] key2 = aes.generateRandomKey();
        byte[] key3 = aes.generateRandomKey();

        try {
            String ciphertext1 = aes.encrypt(plaintext1, iv1, key1);
            String decrypted1 = aes.decrypt(ciphertext1, iv1, key1);
            System.out.println("Participant 1 decrypted message: " + decrypted1);

            String ciphertext2 = aes.encrypt(plaintext2, iv2, key2);
            String decrypted2 = aes.decrypt(ciphertext2, iv2, key2);
            System.out.println("Participant 2 decrypted message: " + decrypted2);

            String ciphertext3 = aes.encrypt(plaintext3, iv3, key3);
            String decrypted3 = aes.decrypt(ciphertext3, iv3, key3);
            System.out.println("Participant 3 decrypted message: " + decrypted3);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}