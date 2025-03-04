import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import java.util.Base64;

public class RSAEncryption1 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSAEncryption1() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public String encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(symmetricKey);
        return Base64.getEncoder().encodeToString(encryptedKey);
    }

    public byte[] decryptSymmetricKey(String encryptedKey) throws Exception {
        byte[] encryptedKeyBytes = Base64.getDecoder().decode(encryptedKey);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedKeyBytes);
    }

    public static void main(String[] args) {
        try {
            RSAEncryption1 rsaEncryption = new RSAEncryption1();

            // 假设我们有一个对称密钥
            byte[] symmetricKey = "ThisIsASymmetricKey".getBytes();

            // 使用RSA加密对称密钥
            String encryptedSymmetricKey = rsaEncryption.encryptSymmetricKey(symmetricKey);
            System.out.println("Encrypted Symmetric Key: " + encryptedSymmetricKey);

            // 使用RSA解密对称密钥
            byte[] decryptedSymmetricKey = rsaEncryption.decryptSymmetricKey(encryptedSymmetricKey);
            System.out.println("Decrypted Symmetric Key: " + new String(decryptedSymmetricKey));

            // 现在你可以使用解密后的对称密钥来加密/解密数据

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}