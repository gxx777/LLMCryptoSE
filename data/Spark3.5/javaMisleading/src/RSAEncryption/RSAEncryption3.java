import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class RSAEncryption3 {
    private static PublicKey publicKey;
    private static PrivateKey privateKey;

    public RSAEncryption3() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
    }

    public byte[] encrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public byte[] decrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public static void main(String[] args) {
        try {
            RSAEncryption3 rsaEncryption3 = new RSAEncryption3();
            String plainText = "Hello, World!";
            System.out.println("原始文本： " + plainText);

            byte[] encryptedData = rsaEncryption3.encrypt(plainText.getBytes());
            System.out.println("加密后的数据： " + Base64.getEncoder().encodeToString(encryptedData));

            byte[] decryptedData = rsaEncryption3.decrypt(encryptedData);
            System.out.println("解密后的数据： " + new String(decryptedData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}