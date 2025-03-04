import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.KeySpec;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ECCEncryption3 {

    // 生成ECC密钥对
    public static KeyPair generateECCKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256); // ECC密钥长度，可以是192, 224, 256等
        return keyGen.generateKeyPair();
    }

    // 使用ECC公钥加密对称密钥
    public static byte[] encryptSymmetricKeyWithECC(PublicKey eccPublicKey, Key symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.ENCRYPT_MODE, eccPublicKey);
        return cipher.doFinal(symmetricKey.getEncoded());
    }

    // 使用ECC私钥解密对称密钥
    public static Key decryptSymmetricKeyWithECC(PrivateKey eccPrivateKey, byte[] encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.DECRYPT_MODE, eccPrivateKey);
        byte[] decryptedSymmetricKey = cipher.doFinal(encryptedSymmetricKey);

        // 假设对称密钥是AES密钥
        KeySpec keySpec = new SecretKeySpec(decryptedSymmetricKey, "AES");
        return SecretKeyFactory.getInstance("AES").generateSecret(keySpec);
    }

    // 使用AES对称密钥加密文件
    public static byte[] encryptFileWithAES(Key aesKey, File file) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);

        byte[] fileContent = Files.readAllBytes(Paths.get(file.getAbsolutePath()));
        byte[] iv = cipher.getIV();
        byte[] encryptedContent = cipher.doFinal(fileContent);

        // 将IV和加密内容合并，以便之后解密
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(iv);
        bos.write(encryptedContent);
        return bos.toByteArray();
    }

    // 使用AES对称密钥解密文件
    public static void decryptFileWithAES(Key aesKey, byte[] encryptedFileContent, File outputFile) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);

        // 分割IV和加密内容
        byte[] iv = new byte[cipher.getBlockSize()];
        System.arraycopy(encryptedFileContent, 0, iv, 0, iv.length);
        byte[] encryptedContent = new byte[encryptedFileContent.length - iv.length];
        System.arraycopy(encryptedFileContent, iv.length, encryptedContent, 0, encryptedContent.length);

        byte[] decryptedContent = cipher.doFinal(encryptedContent);
        Files.write(Paths.get(outputFile.getAbsolutePath()), decryptedContent);
    }

    public static void main(String[] args) {
        try {
            // 生成ECC密钥对
            KeyPair eccKeyPair = generateECCKeyPair();

            // 生成AES对称密钥
            KeyGenerator aesKeyGenerator = KeyGenerator.getInstance("AES");
            aesKeyGenerator.init(128);
            Key aesKey = aesKeyGenerator.generateKey();

            // 使用ECC公钥加密AES对称密钥
            byte[] encryptedAESKey = encryptSymmetricKeyWithECC(eccKeyPair.getPublic(), aesKey);

            // 使用ECC私钥解密AES对称密钥
            Key decryptedAESKey = decryptSymmetricKeyWithECC(eccKeyPair.getPrivate(), encryptedAESKey);

            // 加密文件
            File inputFile = new File("path_to_input_file");
            byte[] encryptedFileContent = encryptFileWithAES(aesKey, inputFile);

            // 解密文件
            File outputFile = new File("path_to_output_file");
            decryptFileWithAES(decryptedAESKey, encryptedFileContent, outputFile);

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}