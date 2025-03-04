import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AsymmetricEncryption4 {

    public static void generateKeys(String publicKeyFile, String privateKeyFile) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        try (FileOutputStream out = new FileOutputStream(publicKeyFile)) {
            out.write(keyPair.getPublic().getEncoded());
        }

        try (FileOutputStream out = new FileOutputStream(privateKeyFile)) {
            out.write(keyPair.getPrivate().getEncoded());
        }
    }

    public static byte[] encryptSymmetricKey(SecretKey symmetricKey, String publicKeyFile) throws Exception {
        byte[] publicKeyBytes = Files.readAllBytes(Paths.get(publicKeyFile));

        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey.getEncoded());

    }

    public static SecretKey decryptSymmetricKey(byte[] encryptedSymmetricKey, String privateKeyFile) throws Exception {

        byte[] privateKeyBytes = Files.readAllBytes(Paths.get(privateKeyFile));
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedSymmetricKey);

        SecretKeySpec secretKeySpec = new SecretKeySpec(decryptedKeyBytes, "AES");
        return secretKeySpec;

    }

    public static void main(String[] args) throws Exception {
        String publicKeyFile = "public_key.pem";
        String privateKeyFile = "private_key.pem";
        String symmetricKeyFile = "symmetric_key.bin";

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey symmetricKey = keyGenerator.generateKey();

        generateKeys(publicKeyFile, privateKeyFile);

        byte[] encryptedKey = encryptSymmetricKey(symmetricKey, publicKeyFile);
        try (FileOutputStream out = new FileOutputStream(symmetricKeyFile)) {
            out.write(encryptedKey);
        }

        FileInputStream fis = new FileInputStream(symmetricKeyFile);
        byte[] encryptedKeyBytes = new byte[fis.available()];
        fis.read(encryptedKeyBytes);
        fis.close();

        SecretKey decryptedKey = decryptSymmetricKey(encryptedKeyBytes, privateKeyFile);

        // Use the decrypted symmetric key for encryption and decryption of data
    }
}