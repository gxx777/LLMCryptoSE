import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

public class AsymmetricEncryption1 {
    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;
    private static final String PADDING = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();

        // 读取对称密钥文件
        byte[] symmetricKey = Files.readAllBytes(Paths.get("symmetric_key.txt"));

        // 使用公钥加密对称密钥
        byte[] encryptedSymmetricKey = encrypt(symmetricKey, keyPair.getPublic());

        // 将加密后的对称密钥写入文件
        try (FileOutputStream fos = new FileOutputStream("encrypted_symmetric_key.txt")) {
            fos.write(encryptedSymmetricKey);
        }

        // 使用私钥解密对称密钥
        byte[] decryptedSymmetricKey = decrypt(encryptedSymmetricKey, keyPair.getPrivate());

        // 将解密后的对称密钥写入文件
        try (FileOutputStream fos = new FileOutputStream("decrypted_symmetric_key.txt")) {
            fos.write(decryptedSymmetricKey);
        }
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] encrypt(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    private static byte[] decrypt(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(PADDING);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }
}