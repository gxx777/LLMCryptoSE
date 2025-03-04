import java.io.*;
import java.nio.file.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Arrays;
import java.util.Base64;

public class AsymmetricEncryption2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public AsymmetricEncryption2() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public String encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSymmetricKey = cipher.doFinal(symmetricKey);
        return Base64.getEncoder().encodeToString(encryptedSymmetricKey);
    }

    public byte[] decryptSymmetricKey(String encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSymmetricKey = cipher.doFinal(Base64.getDecoder().decode(encryptedSymmetricKey));
        return decryptedSymmetricKey;
    }

    public static void main(String[] args) {
        try {
            // 创建一个对称密钥
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey secretKey = keyGenerator.generateKey();

            // 初始化AsymmetricEncryption2对象
            AsymmetricEncryption2 asymmetricEncryption = new AsymmetricEncryption2();

            // 加密对称密钥
            String encryptedSymmetricKey = asymmetricEncryption.encryptSymmetricKey(secretKey.getEncoded());
            System.out.println("Encrypted Symmetric Key: " + encryptedSymmetricKey);

            // 解密对称密钥
            byte[] decryptedSymmetricKey = asymmetricEncryption.decryptSymmetricKey(encryptedSymmetricKey);
            System.out.println("Decrypted Symmetric Key: " + Arrays.toString(decryptedSymmetricKey));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}