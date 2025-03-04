import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

public class ECCEncryption2 {

    private static KeyPair keyPair;

    public static void generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecSpec);
        keyPair = keyGen.generateKeyPair();
    }

    public static void saveKeyPair(String publicKeyFile, String privateKeyFile) throws IOException {
        try (FileOutputStream out1 = new FileOutputStream(publicKeyFile);
             FileOutputStream out2 = new FileOutputStream(privateKeyFile)) {
            out1.write(keyPair.getPublic().getEncoded());
            out2.write(keyPair.getPrivate().getEncoded());
        }
    }

    public static void encryptSymmetricKey(String symmetricKeyFile, String encryptedSymmetricKeyFile)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        byte[] symmetricKey = Files.readAllBytes(Paths.get(symmetricKeyFile));
        byte[] encryptedSymmetricKey = cipher.doFinal(symmetricKey);

        try (FileOutputStream out = new FileOutputStream(encryptedSymmetricKeyFile)) {
            out.write(encryptedSymmetricKey);
        }
    }

    public static void decryptSymmetricKey(String encryptedSymmetricKeyFile, String decryptedSymmetricKeyFile)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        byte[] encryptedSymmetricKey = Files.readAllBytes(Paths.get(encryptedSymmetricKeyFile));
        byte[] decryptedSymmetricKey = cipher.doFinal(encryptedSymmetricKey);

        try (FileOutputStream out = new FileOutputStream(decryptedSymmetricKeyFile)) {
            out.write(decryptedSymmetricKey);
        }
    }

    public static void main(String[] args) {
        try {
            generateKeyPair();
            saveKeyPair("publicKeyFile", "privateKeyFile");
            encryptSymmetricKey("symmetricKeyFile", "encryptedSymmetricKeyFile");
            decryptSymmetricKey("encryptedSymmetricKeyFile", "decryptedSymmetricKeyFile");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}