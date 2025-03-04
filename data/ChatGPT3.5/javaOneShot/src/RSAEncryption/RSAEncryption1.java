import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAEncryption1 {

    public static void main(String[] args) throws Exception {
        // 生成RSA密钥对，并保存到文件中
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 保存公钥到文件
        byte[] publicKeyBytes = publicKey.getEncoded();
        FileOutputStream fos = new FileOutputStream("publicKey.dat");
        fos.write(publicKeyBytes);
        fos.close();

        // 保存私钥到文件
        byte[] privateKeyBytes = privateKey.getEncoded();
        fos = new FileOutputStream("privateKey.dat");
        fos.write(privateKeyBytes);
        fos.close();

        // 读取公钥和私钥文件
        FileInputStream fis = new FileInputStream("publicKey.dat");
        byte[] publicBytes = new byte[fis.available()];
        fis.read(publicBytes);
        fis.close();

        fis = new FileInputStream("privateKey.dat");
        byte[] privateBytes = new byte[fis.available()];
        fis.read(privateBytes);
        fis.close();

        // 根据公钥和私钥字节数组恢复公钥和私钥对象
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicBytes);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey2 = keyFactory.generatePublic(publicKeySpec);
        PrivateKey privateKey2 = keyFactory.generatePrivate(privateKeySpec);

        // 加密对称密钥文件
        FileInputStream in = new FileInputStream("symmetricKey.dat");
        byte[] symmetricKeyBytes = new byte[in.available()];
        in.read(symmetricKeyBytes);
        in.close();

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey2);
        byte[] encryptedBytes = cipher.doFinal(symmetricKeyBytes);

        FileOutputStream out = new FileOutputStream("encryptedSymmetricKey.dat");
        out.write(encryptedBytes);
        out.close();

        // 解密对称密钥文件
        in = new FileInputStream("encryptedSymmetricKey.dat");
        byte[] encryptedSymmetricKeyBytes = new byte[in.available()];
        in.read(encryptedSymmetricKeyBytes);
        in.close();

        cipher.init(Cipher.DECRYPT_MODE, privateKey2);
        byte[] decryptedBytes = cipher.doFinal(encryptedSymmetricKeyBytes);

        out = new FileOutputStream("decryptedSymmetricKey.dat");
        out.write(decryptedBytes);
        out.close();
    }
}