import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

public class AsymmetricEncryption3 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public AsymmetricEncryption3() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public String encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSymmetricKey = cipher.doFinal(symmetricKey);
        return Base64.getEncoder().encodeToString(encryptedSymmetricKey);
    }

    public byte[] decryptSymmetricKey(String encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] bytes = Base64.getDecoder().decode(encryptedSymmetricKey);
        return cipher.doFinal(bytes);
    }

    public static void main(String[] args) {
        try {
            // 创建AsymmetricEncryption3实例
            AsymmetricEncryption3 aes = new AsymmetricEncryption3();

            // 假设我们有一个对称密钥
            byte[] symmetricKey = "ThisIsASymmetricKey".getBytes();

            // 使用公钥加密对称密钥
            String encryptedSymmetricKey = aes.encryptSymmetricKey(symmetricKey);
            System.out.println("Encrypted Symmetric Key: " + encryptedSymmetricKey);

            // 使用私钥解密对称密钥
            byte[] decryptedSymmetricKey = aes.decryptSymmetricKey(encryptedSymmetricKey);
            System.out.println("Decrypted Symmetric Key: " + new String(decryptedSymmetricKey));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}