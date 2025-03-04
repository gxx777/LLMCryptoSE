import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;

public class AsymmetricEncryption4 {

    public static void main(String[] args) throws Exception {
        // 生成对称密钥
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();

        // 使用非对称算法生成密钥对
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 使用公钥加密对称密钥并保存到文件
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(secretKey.getEncoded());
        FileOutputStream keyFileOut = new FileOutputStream("encryptedKey.bin");
        keyFileOut.write(encryptedKey);
        keyFileOut.close();

        // 从文件中读取使用私钥解密对称密钥
        FileInputStream keyFileIn = new FileInputStream("encryptedKey.bin");
        byte[] encryptedKeyBytes = new byte[keyFileIn.available()];
        keyFileIn.read(encryptedKeyBytes);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedKeyBytes);
        SecretKey decryptedKey = new SecretKeySpec(decryptedKeyBytes, "AES");

        // 使用对称密钥加密文件
        FileInputStream inputFile = new FileInputStream("input.txt");
        FileOutputStream encryptedFileOut = new FileOutputStream("encryptedFile.enc");
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, decryptedKey);
        CipherOutputStream cipherOut = new CipherOutputStream(encryptedFileOut, aesCipher);
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = inputFile.read(buffer)) != -1) {
            cipherOut.write(buffer, 0, bytesRead);
        }
        cipherOut.close();
        inputFile.close();

        // 使用对称密钥解密文件
        FileInputStream encryptedFileIn = new FileInputStream("encryptedFile.enc");
        FileOutputStream decryptedFileOut = new FileOutputStream("decryptedFile.txt");
        aesCipher.init(Cipher.DECRYPT_MODE, decryptedKey);
        CipherInputStream cipherIn = new CipherInputStream(encryptedFileIn, aesCipher);
        while ((bytesRead = cipherIn.read(buffer)) != -1) {
            decryptedFileOut.write(buffer, 0, bytesRead);
        }
        cipherIn.close();
        encryptedFileIn.close();
        decryptedFileOut.close();
    }
}