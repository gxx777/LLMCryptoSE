import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AsymmetricEncryption2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public AsymmetricEncryption2() throws NoSuchAlgorithmException {
        // 生成RSA密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    /**
     * 使用公钥加密对称密钥
     *
     * @param symmetricKey 对称密钥
     * @return 加密后的对称密钥
     * @throws Exception 加密过程中可能发生的异常
     */
    public String encryptSymmetricKeyWithPublicKey(byte[] symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSymmetricKey = cipher.doFinal(symmetricKey);
        return Base64.getEncoder().encodeToString(encryptedSymmetricKey);
    }

    /**
     * 使用私钥解密对称密钥
     *
     * @param encryptedSymmetricKey 加密后的对称密钥
     * @return 解密后的对称密钥
     * @throws Exception 解密过程中可能发生的异常
     */
    public byte[] decryptSymmetricKeyWithPrivateKey(String encryptedSymmetricKey) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedSymmetricKey);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedBytes);
    }

    /**
     * 保存私钥到文件
     *
     * @param filePath 文件路径
     * @throws IOException 保存私钥过程中可能发生的IO异常
     */
    public void savePrivateKeyToFile(String filePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(privateKey.getEncoded());
        }
    }

    /**
     * 从文件加载私钥
     *
     * @param filePath 文件路径
     * @throws IOException           加载私钥过程中可能发生的IO异常
     * @throws NoSuchAlgorithmException 加载私钥过程中可能发生的算法异常
     * @throws InvalidKeySpecException  加载私钥过程中可能发生的密钥规范异常
     */
    public void loadPrivateKeyFromFile(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        try  {
            byte[] encoded = Files.readAllBytes(Paths.get(filePath));
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            this.privateKey = keyFactory.generatePrivate(keySpec);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 保存公钥到文件
     *
     * @param filePath 文件路径
     * @throws IOException 保存公钥过程中可能发生的IO异常
     */
    public void savePublicKeyToFile(String filePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(publicKey.getEncoded());
        }
    }

    /**
     * 从文件加载公钥
     *
     * @param filePath 文件路径
     * @throws IOException           加载公钥过程中可能发生的IO异常
     * @throws NoSuchAlgorithmException 加载公钥过程中可能发生的算法异常
     * @throws InvalidKeySpecException  加载公钥过程中可能发生的密钥规范异常
     */
    public void loadPublicKeyFromFile(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            byte[] encoded = Files.readAllBytes(Paths.get(filePath));

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            this.publicKey = keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

}