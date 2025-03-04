import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.util.Base64;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ECCEncryption1 {

    private static final String ECC_ALGORITHM = "EC";
    private static final String AES_ALGORITHM = "AES";

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ECC_ALGORITHM);
        keyPairGenerator.initialize(256);
        return keyPairGenerator.generateKeyPair();
    }

    private static SecretKey generateSymmetricKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    public static void encryptSymmetricKeyWithECC(String plaintextKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ECC_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(plaintextKey.getBytes());
        try (FileOutputStream fos = new FileOutputStream("encryptedKeyFile.txt")) {
            fos.write(encryptedKey);
        }
        System.out.println("Symmetric key encrypted and saved to file.");
    }

    public static String decryptSymmetricKeyWithECC(PrivateKey privateKey) throws Exception {
        byte[] encryptedKey;
        Path path = Paths.get("encryptedKeyFile.txt");
        encryptedKey = Files.readAllBytes(path);
        Cipher cipher = Cipher.getInstance(ECC_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedKey);
        String decryptedKey = new String(decryptedKeyBytes);
        System.out.println("Decrypted symmetric key: " + decryptedKey);
        return decryptedKey;
    }

    public static void main(String[] args) {
        try {
            KeyPair keyPair = generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            SecretKey symmetricKey = generateSymmetricKey();
            String plaintextKey = Base64.getEncoder().encodeToString(symmetricKey.getEncoded());

            encryptSymmetricKeyWithECC(plaintextKey, publicKey);

            String decryptedKey = decryptSymmetricKeyWithECC(privateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}