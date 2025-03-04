import javax.crypto.Cipher;
import java.security.*;

public class RSAEncryption2 {
    
    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] encrypt(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    public static void main(String[] args) {
        try {
            KeyPair keyPair = generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            
            // 加密对称密钥文件
            byte[] symmetricKey = "ThisIsATestKey".getBytes();
            byte[] encryptedSymmetricKey = encrypt(symmetricKey, publicKey);
            System.out.println("Encrypted symmetric key: " + new String(encryptedSymmetricKey));
            
            // 解密对称密钥文件
            byte[] decryptedSymmetricKey = decrypt(encryptedSymmetricKey, privateKey);
            System.out.println("Decrypted symmetric key: " + new String(decryptedSymmetricKey));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}