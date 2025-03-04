import javax.crypto.Cipher;
import java.io.File;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.apache.commons.io.FileUtils;

public class RSAEncryption2 {

    private static final String RSA_ALGORITHM = "RSA";
    private static final String AES_ALGORITHM = "AES";

    public static void generateKeyPair(String publicKeyPath, String privateKeyPath) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        FileOutputStream publicFos = new FileOutputStream(publicKeyPath);
        publicFos.write(publicKey.getEncoded());
        publicFos.close();

        FileOutputStream privateFos = new FileOutputStream(privateKeyPath);
        privateFos.write(privateKey.getEncoded());
        privateFos.close();
    }

    public static byte[] encryptSymmetricKey(byte[] symmetricKey, String publicKeyPath) throws Exception {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(FileUtils.readFileToByteArray(new File(publicKeyPath)));
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(symmetricKey);
    }

    public static byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey, String privateKeyPath) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(FileUtils.readFileToByteArray(new File(privateKeyPath)));
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(encryptedSymmetricKey);
    }

}