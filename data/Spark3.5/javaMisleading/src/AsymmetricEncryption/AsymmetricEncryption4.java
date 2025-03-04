import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

public class AsymmetricEncryption4 {
    private static final String RSA = "RSA";
    private static final String RC4 = "RC4";

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] encryptSymmetricKey(byte[] symmetricKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey);
    }

    public static byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKey);
    }

    public static byte[] encryptData(byte[] data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RC4);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    public static byte[] decryptData(byte[] encryptedData, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RC4);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(encryptedData);
    }

    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 生成对称密钥
        KeyGenerator keyGenerator = KeyGenerator.getInstance(RC4);
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();

        // 加密对称密钥
        byte[] encryptedSymmetricKey = encryptSymmetricKey(secretKey.getEncoded(), publicKey);
        System.out.println("加密后的对称密钥： " + Base64.getEncoder().encodeToString(encryptedSymmetricKey));

        // 解密对称密钥
        byte[] decryptedSymmetricKey = decryptSymmetricKey(encryptedSymmetricKey, privateKey);
        System.out.println("解密后的对称密钥： " + Base64.getEncoder().encodeToString(decryptedSymmetricKey));

        // 使用解密后的对称密钥加密数据
        String data = "Hello, World!";
        byte[] encryptedData = encryptData(data.getBytes(), new SecretKeySpec(decryptedSymmetricKey, RC4));
        System.out.println("加密后的数据： " + Base64.getEncoder().encodeToString(encryptedData));

        // 使用解密后的对称密钥解密数据
        byte[] decryptedData = decryptData(encryptedData, new SecretKeySpec(decryptedSymmetricKey, RC4));
        System.out.println("解密后的数据： " + new String(decryptedData));
    }
}