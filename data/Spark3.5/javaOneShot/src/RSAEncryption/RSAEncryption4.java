import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import javax.crypto.Cipher;

public class RSAEncryption4 {
    private static final String RSA = "RSA";
    private static final String RSA_OAEP_PADDING = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    public static void main(String[] args) throws Exception {
        // 生成RSA密钥对
        KeyPair keyPair = generateRSAKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 读取对称密钥文件
        byte[] symmetricKeyBytes = Files.readAllBytes(Paths.get("symmetric_key.txt"));

        // 使用公钥加密对称密钥
        byte[] encryptedSymmetricKey = encryptSymmetricKey(publicKey, symmetricKeyBytes);

        // 使用私钥解密对称密钥
        byte[] decryptedSymmetricKey = decryptSymmetricKey(privateKey, encryptedSymmetricKey);
    }

    private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] encryptSymmetricKey(PublicKey publicKey, byte[] symmetricKeyBytes) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_OAEP_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKeyBytes);
    }

    public static byte[] decryptSymmetricKey(PrivateKey privateKey, byte[] encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_OAEP_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKey);
    }
}