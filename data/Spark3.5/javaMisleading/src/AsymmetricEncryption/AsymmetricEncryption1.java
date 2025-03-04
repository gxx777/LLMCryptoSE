import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;

public class AsymmetricEncryption1 {

    public static void main(String[] args) throws Exception {
        // 生成RSA密钥对
        KeyPair keyPair = generateRSAKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 生成RC4密钥
        SecretKey secretKey = generateRC4Key();

        // 使用RSA公钥加密RC4密钥
        byte[] encryptedSecretKey = encryptSecretKeyWithRSA(secretKey, publicKey);

        // 使用RSA私钥解密RC4密钥
        SecretKey decryptedSecretKey = decryptSecretKeyWithRSA(encryptedSecretKey, privateKey);

        // 验证解密后的密钥是否与原始密钥相同
        if (Arrays.equals(secretKey.getEncoded(), decryptedSecretKey.getEncoded())) {
            System.out.println("密钥匹配成功");
        } else {
            System.out.println("密钥匹配失败");
        }
    }

    private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static SecretKey generateRC4Key() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("RC4");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private static byte[] encryptSecretKeyWithRSA(SecretKey secretKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(secretKey.getEncoded());
    }

    private static SecretKey decryptSecretKeyWithRSA(byte[] encryptedSecretKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSecretKeyBytes = cipher.doFinal(encryptedSecretKey);
        return new SecretKeySpec(decryptedSecretKeyBytes, "RC4");
    }
}