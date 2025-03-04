import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

public class RSAEncryption4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    // 初始化RSA密钥对
    public RSAEncryption4() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    // 使用公钥加密对称密钥
    public byte[] encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return encryptCipher.doFinal(symmetricKey);
    }

    // 使用私钥解密对称密钥
    public byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey) throws Exception {
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return decryptCipher.doFinal(encryptedSymmetricKey);
    }

    // 保存私钥到文件
    public void savePrivateKey(String filePath) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(privateKey.getEncoded());
        }
    }

    // 从文件加载私钥
    public void loadPrivateKey(String filePath) throws Exception {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            byte[] keyBytes = new byte[fis.available()];
            fis.read(keyBytes);
            this.privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        }
    }

    // 保存公钥到文件
    public void savePublicKey(String filePath) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(publicKey.getEncoded());
        }
    }

    // 从文件加载公钥
    public void loadPublicKey(String filePath) throws Exception {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            byte[] keyBytes = new byte[fis.available()];
            fis.read(keyBytes);
            this.publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));
        }
    }

    public static void main(String[] args) {
        try {
            RSAEncryption4 rsa = new RSAEncryption4();

            // 假设我们有一个对称密钥
            byte[] symmetricKey = "symmetricKey1234567890".getBytes();

            // 加密对称密钥
            byte[] encryptedKey = rsa.encryptSymmetricKey(symmetricKey);

            // 假设私钥保存在一个文件中，并加载它
            rsa.savePrivateKey("privateKey.bin");
            rsa.loadPrivateKey("privateKey.bin");

            // 解密对称密钥
            byte[] decryptedKey = rsa.decryptSymmetricKey(encryptedKey);

            // 检查是否成功解密
            if (java.util.Arrays.equals(symmetricKey, decryptedKey)) {
                System.out.println("Symmetric key has been decrypted successfully.");
            } else {
                System.out.println("Symmetric key decryption failed.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}