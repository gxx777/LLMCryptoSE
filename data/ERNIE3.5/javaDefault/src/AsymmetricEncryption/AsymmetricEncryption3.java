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
        byte[] encryptedKey = cipher.doFinal(symmetricKey);
        return Base64.getEncoder().encodeToString(encryptedKey);
    }

    public byte[] decryptSymmetricKey(String encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedEncryptedKey = Base64.getDecoder().decode(encryptedSymmetricKey);
        return cipher.doFinal(decodedEncryptedKey);
    }

    public static void main(String[] args) {
        try {
            // 创建一个AsymmetricEncryption3实例
            AsymmetricEncryption3 aes = new AsymmetricEncryption3();

            // 假设我们有一个对称密钥
            byte[] symmetricKey = "mySymmetricKey".getBytes();

            // 加密对称密钥
            String encryptedSymmetricKey = aes.encryptSymmetricKey(symmetricKey);
            System.out.println("Encrypted Symmetric Key: " + encryptedSymmetricKey);

            // 解密对称密钥
            byte[] decryptedSymmetricKey = aes.decryptSymmetricKey(encryptedSymmetricKey);
            System.out.println("Decrypted Symmetric Key: " + new String(decryptedSymmetricKey));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}