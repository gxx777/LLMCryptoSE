import java.security.*;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class ECCEncryption2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ECCEncryption2() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("prime256v1")); // 使用指定的椭圆曲线
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public byte[] encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey);
    }

    public byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKey);
    }

    public byte[] encryptData(byte[] data, byte[] symmetricKey) throws Exception {
        SecretKey secretKey = new SecretKeySpec(symmetricKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    public byte[] decryptData(byte[] encryptedData, byte[] symmetricKey) throws Exception {
        SecretKey secretKey = new SecretKeySpec(symmetricKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(encryptedData);
    }

    public static void main(String[] args) {
        try {
            // 示例使用
            ECCEncryption2 eccEncryption = new ECCEncryption2();

            // 生成一个对称密钥
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey aesKey = keyGenerator.generateKey();
            byte[] symmetricKey = aesKey.getEncoded();

            // 加密对称密钥
            byte[] encryptedSymmetricKey = eccEncryption.encryptSymmetricKey(symmetricKey);
            System.out.println("Encrypted Symmetric Key: " + Base64.getEncoder().encodeToString(encryptedSymmetricKey));

            // 解密对称密钥
            byte[] decryptedSymmetricKey = eccEncryption.decryptSymmetricKey(encryptedSymmetricKey);
            System.out.println("Decrypted Symmetric Key: " + Base64.getEncoder().encodeToString(decryptedSymmetricKey));

            // 假设我们有一些要加密的数据
            String originalData = "This is some sensitive data";
            byte[] dataToEncrypt = originalData.getBytes();

            // 使用对称密钥加密数据
            byte[] encryptedData = eccEncryption.encryptData(dataToEncrypt, symmetricKey);
            System.out.println("Encrypted Data: " + Base64.getEncoder().encodeToString(encryptedData));

            // 使用对称密钥解密数据
            byte[] decryptedData = eccEncryption.decryptData(encryptedData, symmetricKey);
            System.out.println("Decrypted Data: " + new String(decryptedData));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}