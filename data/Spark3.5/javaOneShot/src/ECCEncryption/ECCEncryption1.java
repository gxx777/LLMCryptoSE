import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Arrays;
import java.util.Base64;

public class ECCEncryption1 {
    private static final int KEY_SIZE = 256;
    private static final String ALGORITHM = "EC";
    private static final String CIPHER_ALGORITHM = "AES";

    public static void main(String[] args) throws Exception {
        // 生成ECC密钥对
        KeyPair keyPair = generateECCKeyPair();

        // 生成对称密钥
        SecretKey secretKey = generateSecretKey();

        // 加密对称密钥
        byte[] encryptedSecretKey = encryptSecretKey(secretKey, keyPair.getPublic());

        // 解密对称密钥
        SecretKey decryptedSecretKey = decryptSecretKey(encryptedSecretKey, keyPair.getPrivate());

        // 验证解密后的对称密钥是否与原始对称密钥相同
        if (Arrays.equals(secretKey.getEncoded(), decryptedSecretKey.getEncoded())) {
            System.out.println("解密成功");
        } else {
            System.out.println("解密失败");
        }
    }

    private static KeyPair generateECCKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CIPHER_ALGORITHM);
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    private static byte[] encryptSecretKey(SecretKey secretKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(secretKey.getEncoded());
    }

    private static SecretKey decryptSecretKey(byte[] encryptedSecretKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSecretKeyBytes = cipher.doFinal(encryptedSecretKey);
        return new SecretKeySpec(decryptedSecretKeyBytes, CIPHER_ALGORITHM);
    }
}