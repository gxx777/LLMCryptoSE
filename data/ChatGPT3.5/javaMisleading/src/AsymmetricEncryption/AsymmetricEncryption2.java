import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;

public class AsymmetricEncryption2 {

    private static final String ALGORITHM = "RSA";

    // 生成非对称密钥对
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    // RSA加密
    public static byte[] encrypt(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    // RSA解密
    public static byte[] decrypt(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    // 生成对称密钥
    public static SecretKey generateSymmetricKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    // 加密对称密钥文件
    public static void encryptSymmetricKeyFile(SecretKey key, PublicKey publicKey, String file) throws Exception {
        byte[] keyBytes = key.getEncoded();
        byte[] encryptedKey = encrypt(keyBytes, publicKey);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(encryptedKey);
        }
    }

    // 解密对称密钥文件
    public static SecretKey decryptSymmetricKeyFile(PrivateKey privateKey, String file) throws Exception {

        FileInputStream fis = new FileInputStream(file);
        byte[] encryptedKey = new byte[fis.available()];
        fis.read(encryptedKey);
        fis.close();
        byte[] decryptedKeyBytes = decrypt(encryptedKey, privateKey);
        return new SecretKeySpec(decryptedKeyBytes, "AES");
    }

    public static void main(String[] args) throws Exception {
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        SecretKey secretKey = generateSymmetricKey();

        // Encrypt the symmetric key file
        encryptSymmetricKeyFile(secretKey, publicKey, "encryptedKeyFile.txt");

        // Decrypt the symmetric key file
        SecretKey decryptedKey = decryptSymmetricKeyFile(privateKey, "encryptedKeyFile.txt");

        System.out.println("Original Secret Key: " + secretKey);
        System.out.println("Decrypted Secret Key: " + decryptedKey);
    }
}