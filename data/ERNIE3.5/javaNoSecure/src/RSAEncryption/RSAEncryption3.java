import java.security.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class RSAEncryption3 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    // 生成RSA密钥对
    public RSAEncryption3() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    // 使用公钥加密对称密钥
    public String encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(symmetricKey);
        return Base64.getEncoder().encodeToString(encryptedKey);
    }

    // 使用私钥解密对称密钥
    public byte[] decryptSymmetricKey(String encryptedSymmetricKey) throws Exception {
        byte[] encryptedKeyBytes = Base64.getDecoder().decode(encryptedSymmetricKey);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedKeyBytes);
    }

    // 测试方法
    public static void main(String[] args) throws Exception {
        RSAEncryption3 rsaEncryption = new RSAEncryption3();

        // 假设有一个对称密钥
        byte[] symmetricKey = "ThisIsASymmetricKey1234567890".getBytes();

        // 使用公钥加密对称密钥
        String encryptedSymmetricKey = rsaEncryption.encryptSymmetricKey(symmetricKey);
        System.out.println("Encrypted Symmetric Key: " + encryptedSymmetricKey);

        // 使用私钥解密对称密钥
        byte[] decryptedSymmetricKey = rsaEncryption.decryptSymmetricKey(encryptedSymmetricKey);
        System.out.println("Decrypted Symmetric Key: " + new String(decryptedSymmetricKey));
    }
}