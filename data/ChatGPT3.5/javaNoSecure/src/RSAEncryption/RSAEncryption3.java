import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSAEncryption3 {

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public RSAEncryption3() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
    }

    public byte[] encryptSecretKey(byte[] secretKeyBytes) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(secretKeyBytes);
    }

    public byte[] decryptSecretKey(byte[] encryptedSecretKeyBytes) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSecretKeyBytes);
    }

    public byte[] encryptData(byte[] data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    public byte[] decryptData(byte[] encryptedData, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(encryptedData);
    }

    public static void main(String[] args) throws Exception {
        RSAEncryption3 rsaEncryption = new RSAEncryption3();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] encryptedSecretKeyBytes = rsaEncryption.encryptSecretKey(secretKey.getEncoded());
        byte[] decryptedSecretKeyBytes = rsaEncryption.decryptSecretKey(encryptedSecretKeyBytes);

        SecretKey decryptedSecretKey = new SecretKeySpec(decryptedSecretKeyBytes, 0, decryptedSecretKeyBytes.length, "AES");

        String originalData = "Hello, World!";
        byte[] encryptedData = rsaEncryption.encryptData(originalData.getBytes(), decryptedSecretKey);
        byte[] decryptedData = rsaEncryption.decryptData(encryptedData, decryptedSecretKey);

        System.out.println("Original data: " + originalData);
        System.out.println("Decrypted data: " + new String(decryptedData));
    }
}