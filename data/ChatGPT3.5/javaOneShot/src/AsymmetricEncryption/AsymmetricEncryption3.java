import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;

public class AsymmetricEncryption3 {

    private static final String ASYMMETRIC_ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;

    // 生成非对称密钥对
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ASYMMETRIC_ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    // 使用公钥加密对称密钥
    public static byte[] encryptSymmetricKey(byte[] symmetricKey, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey);
    }

    // 使用私钥解密对称密钥
    public static byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKey);
    }

    // 写入对称密钥到文件
    public static void writeSymmetricKeyToFile(byte[] symmetricKey, String filePath) throws IOException {
        FileOutputStream fos = new FileOutputStream(filePath);
        fos.write(symmetricKey);
        fos.close();
    }

    // 从文件读取对称密钥
    public static byte[] readSymmetricKeyFromFile(String filePath) throws IOException {
        File file = new File(filePath);
        FileInputStream fis = new FileInputStream(file);
        byte[] symmetricKey = new byte[(int) file.length()];
        fis.read(symmetricKey);
        fis.close();
        return symmetricKey;
    }

    // 示例代码
    public static void main(String[] args) {
        try {
            // 生成非对称密钥对
            KeyPair keyPair = generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // 加密对称密钥
            byte[] symmetricKey = "ThisIsASecretKey".getBytes();
            byte[] encryptedSymmetricKey = encryptSymmetricKey(symmetricKey, publicKey);

            // 写入加密后的对称密钥到文件
            writeSymmetricKeyToFile(encryptedSymmetricKey, "symmetricKey.txt");

            // 从文件读取对称密钥
            byte[] readSymmetricKey = readSymmetricKeyFromFile("symmetricKey.txt");

            // 解密对称密钥
            byte[] decryptedSymmetricKey = decryptSymmetricKey(readSymmetricKey, privateKey);
            System.out.println("Decrypted Symmetric Key: " + new String(decryptedSymmetricKey));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}