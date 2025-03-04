import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class AsymmetricEncryption2 {

    public static void encryptKeyFile(String keyFile, String publicKeyFile, String outputEncryptedKeyFile) throws Exception {
        FileInputStream fis = new FileInputStream(keyFile);
        byte[] keyBytes = new byte[fis.available()];
        fis.read(keyBytes);
        fis.close();

        PublicKey publicKey = getPublicKey(publicKeyFile);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encryptedKeyBytes = cipher.doFinal(keyBytes);

        FileOutputStream fos = new FileOutputStream(outputEncryptedKeyFile);
        fos.write(encryptedKeyBytes);
        fos.close();
    }

    public static void decryptKeyFile(String encryptedKeyFile, String privateKeyFile, String outputKeyFile) throws Exception {
        FileInputStream fis = new FileInputStream(encryptedKeyFile);
        byte[] encryptedKeyBytes = new byte[fis.available()];
        fis.read(encryptedKeyBytes);
        fis.close();

        PrivateKey privateKey = getPrivateKey(privateKeyFile);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] decryptedKeyBytes = cipher.doFinal(encryptedKeyBytes);

        FileOutputStream fos = new FileOutputStream(outputKeyFile);
        fos.write(decryptedKeyBytes);
        fos.close();
    }

    private static PublicKey getPublicKey(String publicKeyFile) throws Exception {
        FileInputStream fis = new FileInputStream(publicKeyFile);
        byte[] keyBytes = new byte[fis.available()];
        fis.read(keyBytes);
        fis.close();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return keyFactory.generatePublic(keySpec);
    }

    private static PrivateKey getPrivateKey(String privateKeyFile) throws Exception {
        FileInputStream fis = new FileInputStream(privateKeyFile);
        byte[] keyBytes = new byte[fis.available()];
        fis.read(keyBytes);
        fis.close();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        return keyFactory.generatePrivate(keySpec);
    }

    public static void main(String[] args) {
        try {
            // Generate a random symmetric key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey secretKey = keyGen.generateKey();

            // Save the symmetric key to a file
            FileOutputStream keyFileOut = new FileOutputStream("symmetricKey.txt");
            keyFileOut.write(secretKey.getEncoded());
            keyFileOut.close();

            // Encrypt the symmetric key using the public key
            encryptKeyFile("symmetricKey.txt", "publicKey.pem", "encryptedSymmetricKey.txt");

            // Decrypt the symmetric key using the private key
            decryptKeyFile("encryptedSymmetricKey.txt", "privateKey.pem", "decryptedSymmetricKey.txt");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}