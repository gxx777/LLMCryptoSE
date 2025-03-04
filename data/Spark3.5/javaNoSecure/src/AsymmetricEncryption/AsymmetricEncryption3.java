import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

public class AsymmetricEncryption3 {
    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            // 生成密钥对
            KeyPair keyPair = generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // 加密对称密钥
            String symmetricKey = "ThisIsASymmetricKey";
            String encryptedSymmetricKey = encrypt(symmetricKey, publicKey);
            System.out.println("加密后的对称密钥： " + encryptedSymmetricKey);

            // 解密对称密钥
            String decryptedSymmetricKey = decrypt(encryptedSymmetricKey, privateKey);
            System.out.println("解密后的对称密钥： " + decryptedSymmetricKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}