import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AsymmetricEncryption3 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    // 初始化密钥对
    public AsymmetricEncryption3() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // 使用2048位密钥长度
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    // 加密对称密钥
    public String encryptSymmetricKey(SecretKey symmetricKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSymmetricKey = cipher.doFinal(symmetricKey.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedSymmetricKey);
    }

    // 解密对称密钥
    public SecretKey decryptSymmetricKey(String encryptedSymmetricKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSymmetricKeyBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedSymmetricKey));
        return new SecretKeySpec(decryptedSymmetricKeyBytes, "AES");
    }

    // 使用AES加密文件
    public void encryptFile(String filePath, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);

        try (FileInputStream fileInputStream = new FileInputStream(filePath);
             FileOutputStream fileOutputStream = new FileOutputStream(filePath + ".enc")) {

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fileInputStream.read(buffer)) != -1) {
                byte[] encryptedBytes = cipher.update(buffer, 0, bytesRead);
                if (encryptedBytes != null) {
                    fileOutputStream.write(encryptedBytes);
                }
            }
            byte[] finalBytes = cipher.doFinal();
            if (finalBytes != null) {
                fileOutputStream.write(finalBytes);
            }
        }
    }

    // 使用AES解密文件
    public void decryptFile(String filePath, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);

        try (FileInputStream fileInputStream = new FileInputStream(filePath);
             FileOutputStream fileOutputStream = new FileOutputStream(filePath + ".dec")) {

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fileInputStream.read(buffer)) != -1) {
                byte[] decryptedBytes = cipher.update(buffer, 0, bytesRead);
                if (decryptedBytes != null) {
                    fileOutputStream.write(decryptedBytes);
                }
            }
            byte[] finalBytes = cipher.doFinal();
            if (finalBytes != null) {
                fileOutputStream.write(finalBytes);
            }
        }
    }

    public static void main(String[] args) throws Exception {
        AsymmetricEncryption3 encryption = new AsymmetricEncryption3();

    }
}