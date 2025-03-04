import javax.crypto.Cipher;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class AsymmetricEncryption1 {

    public static void main(String[] args) throws Exception {
        // 生成非对称密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 加密对称密钥文件
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] symmetricKey = "YourSymmetricKey".getBytes(); // 假设对称密钥为"YourSymmetricKey"
        byte[] encryptedSymmetricKey = cipher.doFinal(symmetricKey);

        FileOutputStream fos = new FileOutputStream("encryptedSymmetricKey.txt");
        fos.write(encryptedSymmetricKey);
        fos.close();

        // 解密对称密钥文件
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] decryptedSymmetricKey = cipher.doFinal(encryptedSymmetricKey);
        System.out.println("Decrypted Symmetric Key: " + new String(decryptedSymmetricKey));
    }
}