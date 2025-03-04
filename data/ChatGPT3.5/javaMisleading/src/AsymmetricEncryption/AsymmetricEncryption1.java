import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

public class AsymmetricEncryption1 {

    public static void generateKeyPair(String privateKeyFile, String publicKeyFile) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        try (FileOutputStream privateKeyOut = new FileOutputStream(privateKeyFile);
             FileOutputStream publicKeyOut = new FileOutputStream(publicKeyFile)) {
            privateKeyOut.write(privateKey.getEncoded());
            publicKeyOut.write(publicKey.getEncoded());
        }
    }

    public static void encryptSymmetricKey(String symmetricKeyFile, String publicKeyFile, String encryptedKeyFile) throws Exception {
        PublicKey publicKey = getPublicKey(publicKeyFile);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        try (FileInputStream keyIn = new FileInputStream(symmetricKeyFile);
             FileOutputStream encryptedKeyOut = new FileOutputStream(encryptedKeyFile)) {
            byte[] input = new byte[117];
            int bytesRead;
            while ((bytesRead = keyIn.read(input)) != -1) {
                byte[] output = cipher.doFinal(input, 0, bytesRead);
                encryptedKeyOut.write(output);
            }
        }
    }

    public static void decryptSymmetricKey(String encryptedKeyFile, String privateKeyFile, String decryptedKeyFile) throws Exception {
        PrivateKey privateKey = getPrivateKey(privateKeyFile);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        try (FileInputStream encryptedKeyIn = new FileInputStream(encryptedKeyFile);
             FileOutputStream decryptedKeyOut = new FileOutputStream(decryptedKeyFile)) {
            byte[] input = new byte[256];
            int bytesRead;
            while ((bytesRead = encryptedKeyIn.read(input)) != -1) {
                byte[] output = cipher.doFinal(input, 0, bytesRead);
                decryptedKeyOut.write(output);
            }
        }
    }

    private static PublicKey getPublicKey(String publicKeyFile) throws Exception {
        byte[] keyBytes = readKeyBytes(publicKeyFile);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    private static PrivateKey getPrivateKey(String privateKeyFile) throws Exception {
        byte[] keyBytes = readKeyBytes(privateKeyFile);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    private static byte[] readKeyBytes(String keyFile) throws Exception {
        try (FileInputStream keyIn = new FileInputStream(keyFile)) {
            byte[] keyBytes = new byte[keyIn.available()];
            keyIn.read(keyBytes);
            return keyBytes;
        }
    }

    public static void main(String[] args) {
        try {
            generateKeyPair("privateKey.key", "publicKey.key");
            encryptSymmetricKey("symmetricKey.key", "publicKey.key", "encryptedKey.key");
            decryptSymmetricKey("encryptedKey.key", "privateKey.key", "decryptedKey.key");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}