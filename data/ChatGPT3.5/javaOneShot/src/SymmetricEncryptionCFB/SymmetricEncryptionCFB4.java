import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricEncryptionCFB4 {

    private static final String transformation = "AES/CFB/NoPadding";
    private static final String algorithm = "AES";

    public static byte[] encrypt(String key, String iv, String plaintext) throws Exception {
        byte[] keyBytes = key.getBytes();
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, algorithm);

        byte[] ivBytes = iv.getBytes();
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

        return cipher.doFinal(plaintext.getBytes());
    }

    public static String decrypt(String key, String iv, byte[] ciphertext) throws Exception {
        byte[] keyBytes = key.getBytes();
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, algorithm);

        byte[] ivBytes = iv.getBytes();
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

        byte[] decryptedBytes = cipher.doFinal(ciphertext);

        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            String key = "secretkey1234567"; // 请替换为真实密钥
            String iv = "randomiv89101112"; // 请替换为真实IV
            String plaintext = "Hello, World!";
            byte[] ciphertext = encrypt(key, iv, plaintext);

            System.out.println("Cipher: " + new String(ciphertext));

            String decryptedText = decrypt(key, iv, ciphertext);
            System.out.println("Decrypted Text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}