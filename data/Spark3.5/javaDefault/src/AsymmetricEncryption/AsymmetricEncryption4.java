import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class AsymmetricEncryption4 {

    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;

    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 加密对称密钥
        byte[] symmetricKey = generateSymmetricKey();
        byte[] encryptedSymmetricKey = encryptSymmetricKey(symmetricKey, publicKey);

        // 解密对称密钥
        byte[] decryptedSymmetricKey = decryptSymmetricKey(encryptedSymmetricKey, privateKey);

        // 验证解密后的对称密钥是否与原始对称密钥相同
        if (java.util.Arrays.equals(symmetricKey, decryptedSymmetricKey)) {
            System.out.println("加解密成功");
        } else {
            System.out.println("加解密失败");
        }
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] generateSymmetricKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey().getEncoded();
    }

    private static byte[] encryptSymmetricKey(byte[] symmetricKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey);
    }

    private static byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKey);
    }
}