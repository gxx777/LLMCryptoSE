import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.util.Base64;
import java.io.FileOutputStream;
import java.io.FileInputStream;

public class RSAEncryption3 {

    private static final String ALGORITHM_RSA = "RSA";
    private static final String ALGORITHM_CIPHER = "RSA/ECB/PKCS1Padding";

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public RSAEncryption3() {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(ALGORITHM_RSA);
            keyPairGen.initialize(2048, new SecureRandom());
            KeyPair keyPair = keyPairGen.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void savePrivateKey(String filePath) {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(privateKey.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void savePublicKey(String filePath) {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(publicKey.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public byte[] encrypt(byte[] data, PublicKey key) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM_CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] decrypt(byte[] encryptedData, PrivateKey key) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM_CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        RSAEncryption3 rsa = new RSAEncryption3();

        rsa.savePrivateKey("private_key.pem");
        rsa.savePublicKey("public_key.pem");

        String data = "Hello, RSA Encryption!";
        byte[] encryptedData = rsa.encrypt(data.getBytes(), rsa.publicKey);
        System.out.println("Encrypted data: " + Base64.getEncoder().encodeToString(encryptedData));

        byte[] decryptedData = rsa.decrypt(encryptedData, rsa.privateKey);
        System.out.println("Decrypted data: " + new String(decryptedData));
    }
}