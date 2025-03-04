import java.security.*;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;

public class ECCEncryption4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    // 初始化ECC密钥对
    public ECCEncryption4() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("prime256v1")); // 使用指定的椭圆曲线参数
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    // 使用公钥加密对称密钥
    public byte[] encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("ECIES");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return encryptCipher.doFinal(symmetricKey);
    }

    // 使用私钥解密对称密钥
    public byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey) throws Exception {
        Cipher decryptCipher = Cipher.getInstance("ECIES");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return decryptCipher.doFinal(encryptedSymmetricKey);
    }

    public static void main(String[] args) {
        try {
            // 实例化ECC加密对象
            ECCEncryption4 eccEncryption = new ECCEncryption4();

            // 假设我们有一个对称密钥
            byte[] symmetricKey = "mySymmetricKey".getBytes();

            // 使用公钥加密对称密钥
            byte[] encryptedSymmetricKey = eccEncryption.encryptSymmetricKey(symmetricKey);

            // 使用私钥解密对称密钥
            byte[] decryptedSymmetricKey = eccEncryption.decryptSymmetricKey(encryptedSymmetricKey);

            // 输出结果
            System.out.println("Original Symmetric Key: " + new String(symmetricKey));
            System.out.println("Encrypted Symmetric Key: " + new String(encryptedSymmetricKey));
            System.out.println("Decrypted Symmetric Key: " + new String(decryptedSymmetricKey));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}