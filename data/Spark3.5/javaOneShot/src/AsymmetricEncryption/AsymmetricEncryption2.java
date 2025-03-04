import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

public class AsymmetricEncryption2 {
    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;
    private static final String PADDING = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 对称密钥
        String symmetricKey = "ThisIsASymmetricKey";

        // 使用公钥加密对称密钥
        String encryptedSymmetricKey = encrypt(symmetricKey, publicKey);
        System.out.println("Encrypted Symmetric Key: " + encryptedSymmetricKey);

        // 使用私钥解密对称密钥
        String decryptedSymmetricKey = decrypt(encryptedSymmetricKey, privateKey);
        System.out.println("Decrypted Symmetric Key: " + decryptedSymmetricKey);
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    public static String encrypt(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    public static String decrypt(String encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(PADDING);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedData);
    }
}